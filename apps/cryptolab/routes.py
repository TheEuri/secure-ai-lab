import io
import time

from flask import abort, redirect, render_template, request, send_file, url_for
from PIL import Image, UnidentifiedImageError

from apps.cryptolab import cryptolab_bp
from apps.cryptolab import charts
from apps.cryptolab.service import (
    DETECTION_FILE,
    KeyRingUnavailable,
    actor_for,
    get_keyring,
    lab_dir,
    load_json,
    open_store,
    run_pipeline,
)
from apps.root.routes import _require_admin
from common.session import csrf_protect
from cryptolab.cipher import CryptoLabIntegrityError
from cryptolab.experiments import VARIANT_ORDER
from cryptolab.stego import NoPayloadError, PayloadTooLargeError, hide_secret, reveal_secret

MAX_UPLOAD_BYTES = 4 * 1024 * 1024
MAX_PIXELS = 2048 * 2048
MAX_SECRET_CHARS = 2000


def _build_view(results, detection, summary):
    view = {"results": results, "detection": detection, "summary": summary, "charts": {}}
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
            [[av[n]["plaintext"]["mean"] for n in labels], [av[n]["key"]["mean"] for n in labels]],
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
    summary = None
    if (lab_dir() / "events.duckdb").exists():
        with open_store() as store:
            summary = store.summary() if store.count() else None
    return render_template("cryptolab_dashboard.html", user=current, page="admin",
                           **_build_view(results, detection, summary))


@cryptolab_bp.route("/admin/cryptolab/run", methods=["POST"])
@csrf_protect
def run_experiments():
    current, denial = _require_admin()
    if denial:
        return denial
    directory = lab_dir()
    directory.mkdir(parents=True, exist_ok=True)
    with open_store() as store:
        events = 50_000 if store.count() < 1000 else 0
        run_pipeline(store, directory, events=events, quick=True)
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
    actor = actor_for(current)
    with open_store() as store:
        store.record("crypto.encrypt", actor=actor, outcome="success",
                     source_ip=request.remote_addr or "", resource="stego", bytes=len(secret),
                     latency_ms=elapsed)
        store.record("stego.embed", actor=actor, outcome="success",
                     source_ip=request.remote_addr or "", resource="stego", latency_ms=elapsed)
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
    actor = actor_for(current)
    ip = request.remote_addr or ""
    with open_store() as store:
        store.record("stego.extract", actor=actor, outcome="success", source_ip=ip, resource="stego")
        try:
            secret = reveal_secret(ring, carrier).decode("utf-8")
        except NoPayloadError:
            store.record("crypto.decrypt.failure", actor=actor, outcome="failure",
                         source_ip=ip, resource="stego")
            return _stego_page(400, error="Nenhuma mensagem do CryptoLab encontrada nesta imagem.")
        except (CryptoLabIntegrityError, UnicodeDecodeError):
            store.record("crypto.decrypt.failure", actor=actor, outcome="failure",
                         source_ip=ip, resource="stego")
            return _stego_page(400, error="A mensagem foi encontrada, mas falhou na verificação de "
                                          "integridade (HMAC). A imagem foi alterada ou a chave é outra.")
        store.record("crypto.decrypt.success", actor=actor, outcome="success",
                     source_ip=ip, resource="stego")
    return _stego_page(revealed=secret)
