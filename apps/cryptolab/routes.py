import io
import secrets
import time

from flask import abort, redirect, render_template, request, send_file, url_for
from PIL import Image, UnidentifiedImageError

from apps.cryptolab import cryptolab_bp
from apps.cryptolab import charts
from apps.cryptolab.service import (
    DETECTION_FILE,
    INTEGRITY_STATUS,
    LIVE_DIR,
    KeyRingUnavailable,
    StoreBusy,
    actor_for,
    get_keyring,
    lab_dir,
    load_json,
    open_store,
    record_events,
    run_integrity_check,
    run_pipeline,
)
from apps.root.routes import _require_admin
from common.session import csrf_protect
from cryptolab.cipher import BLOCK_BYTES, HEADER_BYTES, TAG_BYTES, CryptoLabIntegrityError
from cryptolab.experiments import VARIANT_ORDER, run_all
from cryptolab.files import FILE_SUFFIX, MAX_NAME_BYTES, open_file, seal_file
from cryptolab.stego import NoPayloadError, PayloadTooLargeError, hide_secret, reveal_secret

MAX_UPLOAD_BYTES = 4 * 1024 * 1024
# A sealed file is the plaintext plus the envelope: name (up to 255 B + 2),
# header, up to one padding block and the HMAC tag.  The decrypt form must
# accept that overhead or a 4 MB file could be encrypted but never opened.
MAX_SEALED_FILE_BYTES = MAX_UPLOAD_BYTES + 2 + MAX_NAME_BYTES + HEADER_BYTES + BLOCK_BYTES + TAG_BYTES
MAX_PIXELS = 2048 * 2048
MAX_SECRET_CHARS = 2000


FEATURE_TEXT = {
    "n_events": "eventos na janela",
    "auth_fail": "falhas de login",
    "decrypt_fail": "falhas de decifragem",
    "file_modified": "arquivos críticos alterados",
    "distinct_ips": "IPs diferentes",
    "distinct_resources": "recursos diferentes",
    "off_hours_ratio": "fora do horário",
    "bytes_sum": "bytes transferidos",
}
RULE_TEXT = {
    "login_bruteforce": "10 ou mais falhas de login",
    "decrypt_storm": "5 ou mais falhas de decifragem",
    "file_modified": "Arquivo crítico alterado",
    "off_hours_access": "Madrugada com muitos IPs ou recursos",
    "event_flood": "Volume acima do normal (percentil 99,9)",
}
LABEL_TEXT = {
    "normal": "uso normal",
    "bruteforce": "força bruta no login",
    "decrypt_storm": "tentativas de decifrar",
    "file_tamper": "arquivo adulterado",
    "atypical_access": "acesso atípico",
    "event_flood": "inundação de eventos",
}


def _feature_value(name, value):
    if name == "off_hours_ratio":
        return f"{value:.0%}"
    return charts.compact_number(value) if value >= 1000 else f"{value:g}"


def _alert_view(alert):
    """Turn one detector record into plain-language columns for the table."""

    by_model = alert.get("isolation_forest")
    fired = alert.get("rules_fired")
    if fired is None:  # detection.json written before rules were itemised
        fired = ["(regra não identificada)"] if alert.get("rules") else []
    if by_model is None:
        detector = "IA" if not fired else "Regra"
    elif by_model and fired:
        detector = "IA + regra"
    elif by_model:
        detector = "Só IA"
    else:
        detector = "Só regra"
    features = alert.get("features") or {}
    why = []
    for name in (alert.get("reasons") or "").split(","):
        name = name.strip()
        if name in FEATURE_TEXT:
            text = FEATURE_TEXT[name]
            why.append(f"{text}: {_feature_value(name, features[name])}" if name in features else text)
        elif name:
            why.append(name)
    label = alert.get("label")
    return {
        "actor": alert.get("actor"), "window_start": alert.get("window_start"),
        "score": alert.get("score", 0.0), "detector": detector,
        "detector_css": "ok" if detector == "IA + regra" else "warn",
        "why": why, "rules": [RULE_TEXT.get(r, r) for r in fired],
        "label": LABEL_TEXT.get(label, label) if label else "evento real do sistema (sem rótulo)",
        "hit": None if label is None else label != "normal",
    }


def _pattern_view(results):
    """Data, chart and plain-language verdict for "Existem padrões na saída?"."""

    stats, patterns = results["statistics"], results["conclusions"]["patterns"]
    labels = list(VARIANT_ORDER)
    rows = [{"name": n, "entropy_text": stats[n]["text"]["entropy_bits_per_byte"],
             "entropy_pattern": stats[n]["pattern"]["entropy_bits_per_byte"],
             "chi2_p": stats[n]["text"]["chi2_p_value"],
             "repeated": stats[n]["pattern"]["repeated_blocks"],
             "reasons": patterns.get(n, [])} for n in labels]
    clean = [r["name"] for r in rows if not r["reasons"]]
    leaky = [r["name"] for r in rows if r["reasons"]]
    def _join(names):
        return ", ".join(names[:-1]) + " e " + names[-1] if len(names) > 1 else "".join(names)

    conclusion = (
        f"Conclusão: só {_join(clean) or 'nenhuma variante'} produzem saída sem padrão "
        "(entropia perto de 8 bits por byte, histograma uniforme e nenhum bloco repetido). "
        f"{_join(leaky) or 'Nenhuma'} deixam padrões visíveis. "
        "A SBX com 10 rodadas em ECB continua repetindo blocos: a cifra forte não basta, "
        "o modo de encadeamento (CBC) é o que elimina a repetição.")
    chart_entropy = charts.bar_chart(
        [[r["entropy_text"] for r in rows], [r["entropy_pattern"] for r in rows]], labels,
        series_names=("texto em português", "entrada repetitiva"), y_max=8,
        title="Entropia por byte (ideal: 8 bits)")
    chart_repeated = charts.hbar_chart(
        [r["repeated"] for r in rows], labels, row=40, label_w=120, width=560,
        title="Blocos de 16 bytes repetidos na saída")
    return {"rows": rows, "conclusion": conclusion,
            "chart_entropy": chart_entropy, "chart_repeated": chart_repeated}


def _build_view(results, detection, summary):
    view = {"results": results, "detection": detection, "summary": summary, "charts": {}}
    if detection:
        view["alerts"] = [_alert_view(a) for a in (detection.get("top") or [])[:10]]
        view["rule_only_alerts"] = [_alert_view(a) for a in detection.get("rule_only") or []]
    if results and results.get("statistics") and results.get("conclusions"):
        view["patterns_view"] = _pattern_view(results)
    c = view["charts"]
    if summary and summary["per_hour"]:
        hours = summary["per_hour"]
        x_labels = [str(h[0])[5:13] for h in hours]
        c["timeline"] = charts.line_chart(
            [[h[1] for h in hours]], series_names=("eventos/hora",), x_labels=x_labels,
            title="Eventos por hora")
        c["timeline_fail"] = charts.line_chart(
            [[], [h[2] for h in hours], [h[3] for h in hours]],
            series_names=("", "falhas/hora", "eventos de ataque injetados (rótulo)"),
            x_labels=x_labels, title="Falhas e ataques por hora")
        c["by_type"] = charts.hbar_chart(
            [t[1] for t in summary["by_type"]], [t[0] for t in summary["by_type"]],
            title="Eventos por tipo")
    if detection and detection.get("metrics"):
        names = ("isolation_forest", "rules", "hybrid")
        c["detection"] = charts.bar_chart(
            [[detection["metrics"][n][m] for n in names] for m in ("precision", "recall", "f1")],
            ["Isolation Forest", "Regras", "Híbrido"], series_names=("precisão", "recall", "F1"),
            y_max=1, percent=True, title="Qualidade dos detectores")
    if results:
        labels = list(VARIANT_ORDER)
        av = results["avalanche"]
        c["avalanche"] = charts.bar_chart(
            [[av[n]["plaintext"].get("body_mean", av[n]["plaintext"]["mean"]) for n in labels],
             [av[n]["key"].get("body_mean", av[n]["key"]["mean"]) for n in labels]],
            labels, series_names=("1 bit no texto claro", "1 bit na chave"), y_max=1, percent=True,
            title="Efeito avalanche por variante")
        c["avalanche_hist"] = {
            n: charts.histogram(av[n]["plaintext"]["histogram"], css=f"series-{i}",
                                title=f"Distribuição avalanche {n}")
            for i, n in enumerate(("sbx-1r-ecb", "sbx-10r-cbc"))}
        c["byte_hist"] = {
            n: charts.histogram(results["statistics"][n]["text"]["histogram"], css=f"series-{i}",
                                title=f"Histograma de bytes {n}")
            for i, n in enumerate(("xor-repeating", "sbx-10r-cbc"))}
        c["sac"] = {k: charts.heatmap(v["matrix"], title=f"SAC {k}") for k, v in results["sac"].items()}
        bf = results["brute_force"]
        c["bruteforce"] = charts.bar_chart(
            [[bf[n]["keys_per_second"] for n in labels]], labels, title="Chaves testadas por segundo")
    return view


@cryptolab_bp.route("/admin/cryptolab")
def dashboard():
    current, denial = _require_admin()
    if denial:
        return denial
    results = load_json("results.json")
    detection = load_json(DETECTION_FILE)
    summary, store_busy = None, False
    if (lab_dir() / "events.duckdb").exists():
        try:
            with open_store() as store:
                summary = store.summary() if store.count() else None
        except StoreBusy:
            store_busy = True
    return render_template("cryptolab_dashboard.html", user=current, page="admin",
                           store_busy=store_busy, integrity=load_json(INTEGRITY_STATUS),
                           live=load_json(f"{LIVE_DIR}/results.json"),
                           **_build_view(results, detection, summary))


@cryptolab_bp.route("/admin/cryptolab/integrity", methods=["POST"])
@csrf_protect
def integrity_check():
    current, denial = _require_admin()
    if denial:
        return denial
    try:
        ring = get_keyring()
    except KeyRingUnavailable:
        return redirect(url_for("cryptolab.dashboard"))
    run_integrity_check(ring, actor_for(current), request.remote_addr or "")
    return redirect(url_for("cryptolab.dashboard") + "#integrity-title")


@cryptolab_bp.route("/admin/cryptolab/run", methods=["POST"])
@csrf_protect
def run_experiments():
    current, denial = _require_admin()
    if denial:
        return denial
    directory = lab_dir()
    directory.mkdir(parents=True, exist_ok=True)
    full = load_json("results.json")
    try:
        with open_store() as store:
            if full and not full.get("quick"):
                # keep the full run cited in the report; the live demo goes elsewhere
                run_all(store, directory / LIVE_DIR, quick=True)
            else:
                events = 50_000 if store.count() < 1000 else 0
                run_pipeline(store, directory, events=events, quick=True)
    except StoreBusy:
        return redirect(url_for("cryptolab.dashboard"))
    return redirect(url_for("cryptolab.dashboard"))


@cryptolab_bp.route("/admin/cryptolab/img/<name>")
def image(name):
    current, denial = _require_admin()
    if denial:
        return denial
    results = load_json("results.json") or {}
    if name not in set(results.get("images", ())):
        abort(404)
    path = lab_dir() / name
    if not path.is_file():
        abort(404)
    return send_file(path, mimetype="image/png")


def _stego_page(status=200, **context):
    return render_template("cryptolab_stego.html", page="admin",
                           max_secret=MAX_SECRET_CHARS, **context), status


def _read_upload(field):
    upload = request.files.get(field)
    if upload is None:
        raise ValueError("Envie uma imagem.")
    data = upload.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("Imagem maior que 4 MB.")
    try:
        img = Image.open(io.BytesIO(data))
        if img.width * img.height > MAX_PIXELS:
            raise ValueError("Imagem com dimensões acima do limite (2048×2048).")
        img.load()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("Arquivo não é uma imagem válida.") from exc
    return img.convert("RGB")


@cryptolab_bp.route("/admin/cryptolab/stego", methods=["GET"])
def stego():
    current, denial = _require_admin()
    if denial:
        return denial
    return _stego_page()


@cryptolab_bp.route("/admin/cryptolab/stego/hide", methods=["POST"])
@csrf_protect
def stego_hide():
    current, denial = _require_admin()
    if denial:
        return denial
    try:
        ring = get_keyring()
    except KeyRingUnavailable:
        return _stego_page(503, error="Chave mestra do CryptoLab não configurada (CRYPTOLAB_MASTER_KEYS).")
    secret = request.form.get("secret", "")
    if not secret or len(secret) > MAX_SECRET_CHARS:
        return _stego_page(400, error=f"Informe um segredo de 1 a {MAX_SECRET_CHARS} caracteres.")
    try:
        cover = _read_upload("cover")
    except ValueError as exc:
        return _stego_page(400, error=str(exc))
    started = time.perf_counter()
    try:
        stego_image = hide_secret(ring, cover, secret.encode("utf-8"))
    except PayloadTooLargeError:
        return _stego_page(400, error="O segredo cifrado excede a capacidade da imagem; use uma imagem maior.")
    elapsed = (time.perf_counter() - started) * 1000
    common = {"actor": actor_for(current), "source_ip": request.remote_addr or "",
              "resource": "stego", "latency_ms": elapsed}
    record_events([("crypto.encrypt", {**common, "outcome": "success", "bytes": len(secret)}),
                   ("stego.embed", {**common, "outcome": "success"})])
    buf = io.BytesIO()
    stego_image.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png", as_attachment=True, download_name="stego.png")


@cryptolab_bp.route("/admin/cryptolab/stego/reveal", methods=["POST"])
@csrf_protect
def stego_reveal():
    current, denial = _require_admin()
    if denial:
        return denial
    try:
        ring = get_keyring()
    except KeyRingUnavailable:
        return _stego_page(503, error="Chave mestra do CryptoLab não configurada (CRYPTOLAB_MASTER_KEYS).")
    try:
        carrier = _read_upload("image")
    except ValueError as exc:
        return _stego_page(400, error=str(exc))
    common = {"actor": actor_for(current), "source_ip": request.remote_addr or "",
              "resource": "stego"}
    secret, error = None, None
    try:
        secret = reveal_secret(ring, carrier).decode("utf-8")
    except NoPayloadError:
        error = "Nenhuma mensagem do CryptoLab encontrada nesta imagem."
    except (CryptoLabIntegrityError, UnicodeDecodeError):
        error = ("A mensagem foi encontrada, mas falhou na verificação de integridade (HMAC). "
                 "A imagem foi alterada ou a chave é outra.")
    outcome = "success" if error is None else "failure"
    record_events([("stego.extract", {**common, "outcome": outcome}),
                   ("crypto.decrypt.success" if error is None else "crypto.decrypt.failure",
                    {**common, "outcome": outcome})])
    if error:
        return _stego_page(400, error=error)
    return _stego_page(revealed=secret)


def _files_page(status=200, **context):
    return render_template("cryptolab_files.html", page="admin",
                           max_mb=MAX_UPLOAD_BYTES // (1024 * 1024), **context), status


def _read_file_upload(limit=MAX_UPLOAD_BYTES):
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        raise ValueError("Envie um arquivo.")
    data = upload.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"Arquivo maior que {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
    return upload.filename, data


@cryptolab_bp.route("/admin/cryptolab/files", methods=["GET"])
def files():
    current, denial = _require_admin()
    if denial:
        return denial
    return _files_page()


@cryptolab_bp.route("/admin/cryptolab/files/encrypt", methods=["POST"])
@csrf_protect
def files_encrypt():
    current, denial = _require_admin()
    if denial:
        return denial
    try:
        ring = get_keyring()
    except KeyRingUnavailable:
        return _files_page(503, error="Chave mestra do CryptoLab não configurada (CRYPTOLAB_MASTER_KEYS).")
    try:
        filename, data = _read_file_upload()
    except ValueError as exc:
        return _files_page(400, error=str(exc))
    started = time.perf_counter()
    blob = seal_file(ring, filename, data)
    record_events([("crypto.encrypt", {
        "actor": actor_for(current), "source_ip": request.remote_addr or "", "resource": "file",
        "outcome": "success", "bytes": len(data),
        "latency_ms": (time.perf_counter() - started) * 1000})])
    return send_file(io.BytesIO(blob), mimetype="application/octet-stream", as_attachment=True,
                     download_name="arquivo-" + secrets.token_hex(4) + FILE_SUFFIX)


@cryptolab_bp.route("/admin/cryptolab/files/decrypt", methods=["POST"])
@csrf_protect
def files_decrypt():
    current, denial = _require_admin()
    if denial:
        return denial
    try:
        ring = get_keyring()
    except KeyRingUnavailable:
        return _files_page(503, error="Chave mestra do CryptoLab não configurada (CRYPTOLAB_MASTER_KEYS).")
    try:
        _, blob = _read_file_upload(MAX_SEALED_FILE_BYTES)
    except ValueError as exc:
        return _files_page(400, error=str(exc))
    common = {"actor": actor_for(current), "source_ip": request.remote_addr or "", "resource": "file"}
    try:
        name, data = open_file(ring, blob)
    except CryptoLabIntegrityError:
        record_events([("crypto.decrypt.failure", {**common, "outcome": "failure", "bytes": len(blob)})])
        return _files_page(400, error=("O arquivo falhou na verificação de integridade (HMAC-SHA256): "
                                       "foi alterado ou foi cifrado com outra chave. Nada foi decifrado."))
    record_events([("crypto.decrypt.success", {**common, "outcome": "success", "bytes": len(data)})])
    return send_file(io.BytesIO(data), mimetype="application/octet-stream", as_attachment=True,
                     download_name=name)
