# Projeto 2 — CryptoLab (Sistema Criptográfico + Análise de Ataques) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Acrescentar ao SecureBoard AI um laboratório criptográfico ("CryptoLab") com cifra simétrica própria de chave dinâmica, esteganografia, armazenamento analítico de eventos, detecção de anomalias por IA, simulação de ataques (força bruta, diferencial, estatístico) e dashboard administrativo — mais relatório e slides.

**Architecture:** Pacote Python independente `cryptolab/` (sem Flask) com um módulo por responsabilidade; o SecureBoard expõe o dashboard via blueprint `apps/cryptolab` (somente admin, CSRF) e comandos `flask cryptolab-*`. Eventos vão para DuckDB (colunar) com exportação Parquet; anomalias via IsolationForest (scikit-learn) comparado a um baseline de regras, avaliado contra rótulos de verdade da simulação. Fluxo da arquitetura do enunciado: Entrada → Cripto (SBX-128 + AES-256-GCM de referência) → Esteganografia → Big Data → IA → Dashboard.

**Tech Stack:** Python 3.12, Flask 3.1 (existente), `cryptography` (HKDF/HMAC/AES-GCM, existente), Pillow (existente), `duckdb`, `numpy`, `scikit-learn` (novos, versões fixadas no `requirements.txt`), `unittest` (padrão do repo), Chrome headless para PDF.

**Spec:** `/Users/Pedro/Downloads/Aula 26 - Projeto 2.pdf` + feedback do Projeto 1 (gerenciamento de chaves simétricas; relatório incompleto).

## Global Constraints

- Chave secreta deve influenciar a cifragem e **não pode ser fixa** → chave por mensagem derivada (HKDF + salt aleatório) de chave mestra com `key_id` e rotação.
- Cifragem deve combinar **XOR, substituição, permutação e blocos**, com **difusão/confusão**.
- Ataques: força bruta (calcular espaço de chave + medir/avaliar viabilidade), diferencial (alterar 1 bit/caractere, comparar, medir), estatístico (padrões, frequência de caracteres).
- Responder: efeito avalanche? padrões na saída? ataque mais eficaz? o sistema é seguro? (justificado com números).
- Big Data: logs de operações criptográficas, tentativas/falhas de autenticação, eventos de anomalia, padrões de comportamento, grandes conjuntos experimentais (≥ 1.000.000 eventos).
- Anomalias detectáveis: tentativas de autenticação incomuns, falhas de descriptografia elevadas, alterações inesperadas em arquivos, padrões atípicos de acesso, geração incomum de eventos.
- Dashboard: ataques, anomalias e resultados de testes.
- Entregas: relatório + slides (descrição do algoritmo, funcionamento, testes, resultados, conclusão) e registro de uso de IA (feedback do Projeto 1).
- Feedback P1: não depender de uma única chave simétrica para operações/usuários diferentes → separação de domínio por finalidade e por conversa nas mensagens privadas do SecureBoard.
- CSP do app proíbe script/style inline: gráficos em SVG com atributos de apresentação; CSS em arquivo estático.
- Commits: Conventional Commits em inglês, sem linha de co-autoria. **Não fazer push.**
- Testes existentes não podem regredir (4 falhas ambientais pré-existentes: `data/secureboard.db` local e symlink `/private` do macOS).

## Review Focus

1. Ciphertext adulterado ou chave/`key_id` errado → deve falhar fechado (`CryptoLabIntegrityError`), nunca devolver lixo; registrado como `decrypt.failure`.
2. Payload maior que a capacidade da imagem / imagem sem payload / imagem recomprimida → erro claro, sem exceção crua.
3. Mensagens privadas antigas (crypto_version 1) continuam legíveis após introduzir a v2 por conversa.
4. Dashboard acessado sem dados gerados (nenhum experimento rodado ainda) → página renderiza com estado vazio, não 500.
5. Usuário comum em `/admin/cryptolab*` → 403 + evento `authz.admin.denied`; POST sem CSRF → 403.

---

### Task 1: Dependências e chaveiro (KeyManager)

**Files:**
- Modify: `requirements.txt` (adicionar `duckdb`, `numpy`, `scikit-learn` fixados)
- Create: `cryptolab/__init__.py`, `cryptolab/keys.py`
- Test: `tests/test_cryptolab_keys.py`

**Interfaces — Produces:**
- `class KeyRing`: `KeyRing(keys: dict[int, bytes], active_id: int)`; `KeyRing.from_env(value: str) -> KeyRing` (formato `"1:<b64url32>,2:<b64url32>"`, ativo = maior id); `generate(cls) -> KeyRing`; `rotate() -> int` (novo id = max+1); `master(key_id) -> bytes` (`UnknownKeyError` se ausente); `active_id`.
- `derive_key(master: bytes, salt: bytes, purpose: str, length=32) -> bytes` — HKDF-SHA256, `info = b"cryptolab:v1:" + purpose`.
- Purposes fixos: `"enc"`, `"mac"`, `"round"`, `"sbox"`, `"perm"`, `"stego"`.

- [ ] Testes: chaves de 32 bytes obrigatórias (31/33 → `ValueError`); `derive_key` determinístico para mesmos args; muda com salt diferente e com purpose diferente (enc ≠ mac); `rotate` mantém chave antiga acessível e muda `active_id`; `from_env` round-trip.
- [ ] Rodar → FAIL; implementar; rodar → PASS; commit `feat(cryptolab): add key ring with hkdf domain separation`.

### Task 2: Cifra SBX-128 (SPN própria) + modos + envelope autenticado

**Files:**
- Create: `cryptolab/cipher.py`
- Test: `tests/test_cryptolab_cipher.py`

**Design (decidido):**
- Bloco 16 bytes, `ROUNDS = 10`. Chave de cifra `k_enc` (32 B).
- Key schedule a partir de `k_enc`: round keys = HKDF-Expand(`purpose="round"`, 16·(R+1) bytes); S-box = Fisher–Yates de `range(256)` com fluxo HKDF (`"sbox"`, amostragem por rejeição); permutação de bytes = Fisher–Yates de `range(16)` (`"perm"`). Inversas pré-computadas.
- Rodada r (1..R): `state ^= rk[r-1]` (XOR) → `sbox` (substituição/confusão) → `perm` (permutação) → `MixColumns` AES em GF(2⁸) se `r < R` (difusão). Final `state ^= rk[R]`.
- `class BlockCipher(k_enc: bytes, rounds: int = 10)`: `encrypt_block(bytes16) -> bytes16`, `decrypt_block`.
- Modos: `ecb_encrypt/ecb_decrypt(cipher, data)`, `cbc_encrypt(cipher, data, iv)/cbc_decrypt`, PKCS#7 (`PaddingError`).
- Envelope `seal(keyring, plaintext, *, salt=None, iv=None) -> bytes`: `b"SBX1" | key_id(1) | salt(16) | iv(16) | ct | tag(32)`; `k_enc`,`k_mac` = `derive_key(master, salt, "enc"/"mac")`; tag = HMAC-SHA256(`k_mac`, tudo antes do tag) (encrypt-then-MAC). `open_sealed(keyring, blob) -> bytes` verifica tag em tempo constante antes de decifrar; qualquer falha → `CryptoLabIntegrityError`.
- Variantes para análise (`VARIANTS`): `"xor-repeating"` (XOR com chave de 4 bytes repetida — didática, vulnerável), `"sbx-1r-ecb"` (1 rodada, ECB), `"sbx-10r-ecb"`, `"sbx-10r-cbc"` (envelope completo), `"aes-256-gcm"` (referência via `cryptography`). Função `get_variant(name) -> Variant` com `encrypt(key: bytes, pt: bytes, *, iv=None) -> bytes`.

- [ ] Testes: `decrypt_block(encrypt_block(x)) == x` para 200 blocos aleatórios; CBC/ECB round-trip com tamanhos 0,1,15,16,17,1000; `open_sealed(seal(m)) == m`; dois `seal` da mesma mensagem diferem (salt/IV); flip de 1 bit em qualquer posição do blob → `CryptoLabIntegrityError`; `key_id` desconhecido → `CryptoLabIntegrityError`; após `rotate()`, blob antigo ainda abre e novo usa novo id; S-box é permutação de 0..255 e muda com a chave; vetor fixo (chave/IV/salt fixos) gera ciphertext estável (regressão).
- [ ] FAIL → implementar → PASS → commit `feat(cryptolab): add sbx-128 spn cipher with authenticated envelope`.

### Task 3: Esteganografia LSB com ordem de pixels derivada da chave

**Files:**
- Create: `cryptolab/stego.py`
- Test: `tests/test_cryptolab_stego.py`

**Interfaces — Produces:**
- `capacity_bytes(image: PIL.Image) -> int` (3 bits/pixel RGB, menos cabeçalho 8 B).
- `embed(cover: Image, payload: bytes, *, stego_key: bytes | None) -> Image` — cabeçalho `b"STG1" + len(u32)`; com `stego_key`, posições embaralhadas por PRNG (`random.Random(int.from_bytes(sha256(stego_key)))`); sem chave, sequencial. `PayloadTooLargeError`.
- `extract(image, *, stego_key) -> bytes` — `NoPayloadError` se magic ausente.
- `psnr(a, b) -> float`; `lsb_chi_square(image, fraction: float) -> float` (p-valor do teste de pares de valores de Westfeld–Pfitzmann na primeira `fraction` dos pixels).
- `hide_secret(keyring, cover, plaintext) -> Image` = `embed(cover, seal(...), stego_key=derive_key(master, b"", "stego"))`; `reveal_secret(keyring, image) -> bytes`.

- [ ] Testes: round-trip sequencial e embaralhado; payload > capacidade → `PayloadTooLargeError`; imagem limpa → `NoPayloadError`; chave stego errada → `NoPayloadError` ou `CryptoLabIntegrityError`; PSNR > 50 dB com payload pequeno; alterar 1 pixel do stego que carrega payload → `reveal_secret` falha fechado; salvar/carregar PNG preserva; JPEG não suportado (converter para RGB PNG).
- [ ] FAIL → implementar → PASS → commit `feat(cryptolab): add keyed lsb steganography`.

### Task 4: Event store (Big Data) com DuckDB + simulação de 1M eventos

**Files:**
- Create: `cryptolab/events.py`, `cryptolab/simulate.py`
- Test: `tests/test_cryptolab_events.py`

**Interfaces — Produces:**
- Schema `events(ts TIMESTAMP, event_type VARCHAR, actor VARCHAR, source_ip VARCHAR, resource VARCHAR, outcome VARCHAR, bytes BIGINT, latency_ms DOUBLE, label VARCHAR)`; `anomalies(window_start TIMESTAMP, actor VARCHAR, score DOUBLE, detector VARCHAR, reasons VARCHAR, label VARCHAR)`.
- `class EventStore(path: str | Path)` (`":memory:"` aceito): `record(event_type, *, actor, outcome, source_ip="127.0.0.1", resource="", bytes=0, latency_ms=0.0, label=None, ts=None)`; `bulk_insert_arrays(cols: dict[str, np.ndarray])`; `count() -> int`; `query(sql, params=()) -> list[tuple]`; `summary() -> dict` (totais por tipo/outcome, eventos/minuto, top atores com falhas); `export_parquet(dir) -> Path`; `ingest_secureboard(sqlite_path) -> int` (lê `security_events`, mapeia para o schema, `label=None`).
- Tipos de evento: `auth.login.success|failure`, `crypto.encrypt`, `crypto.decrypt.success|failure`, `file.read|file.modified`, `stego.embed|extract`, `anomaly.detected`.
- `simulate(store, n_events=1_000_000, *, seed=42, days=7) -> dict` — numpy vetorizado: ~200 atores normais (horário comercial, IPs estáveis, falhas raras) + anomalias injetadas com `label`: `bruteforce` (rajada de `auth.login.failure`), `decrypt_storm` (picos de `crypto.decrypt.failure`), `file_tamper` (`file.modified` em recurso estável), `atypical_access` (madrugada + IPs novos + muitos recursos), `event_flood` (taxa 20× maior). Retorna contagens por label e tempo de ingestão.

- [ ] Testes (com `n_events=20_000`): `count()` == n; todos os 5 labels presentes; `summary()` chaves esperadas; `record` + `query` funcionam; `export_parquet` gera arquivo lido de volta com mesma contagem; `ingest_secureboard` em SQLite temporário com 3 eventos → 3 linhas.
- [ ] FAIL → implementar → PASS → commit `feat(cryptolab): add duckdb event store and synthetic workload`.

### Task 5: Detecção de anomalias (IA)

**Files:**
- Create: `cryptolab/anomaly.py`
- Test: `tests/test_cryptolab_anomaly.py`

**Interfaces — Produces:**
- `FEATURES = ("n_events","auth_fail","decrypt_fail","file_modified","distinct_ips","distinct_resources","off_hours_ratio","bytes_sum")` — agregadas em SQL por `(actor, janela de 5 min)`.
- `build_feature_windows(store) -> (keys: list[tuple], X: np.ndarray, labels: list[str|None])` — label da janela = label anômalo majoritário ou `"normal"`.
- `detect(store, *, contamination=0.02, seed=42) -> DetectionReport` — `log1p` + `StandardScaler` + `IsolationForest(n_estimators=200)`; baseline de regras (`auth_fail≥10`, `decrypt_fail≥5`, `file_modified≥1 em recurso marcado estável`, `off_hours_ratio>0.8 e distinct_ips≥3`, `n_events>P99.5`); grava em `anomalies` e emite `anomaly.detected`; `reasons` = features com z-score > 3.
- `DetectionReport`: `metrics: dict[detector -> {precision, recall, f1}]`, `per_label_recall: dict[detector -> dict[label -> float]]`, `n_windows`, `n_flagged`, `top: list[dict]`.

- [ ] Testes (sim 30k eventos): `n_windows>0`; IsolationForest recall ≥ 0.7 para `bruteforce` e `event_flood`; precisão global de pelo menos um detector ≥ 0.5; `anomalies` populada; reasons contém `auth_fail` em janelas `bruteforce`.
- [ ] FAIL → implementar → PASS → commit `feat(cryptolab): detect anomalous behaviour with isolation forest`.

### Task 6: Ataques e métricas (força bruta, diferencial, estatístico)

**Files:**
- Create: `cryptolab/attacks.py`, `cryptolab/experiments.py`
- Test: `tests/test_cryptolab_attacks.py`

**Interfaces — Produces (`attacks.py`):**
- `brute_force(variant, *, unknown_bits=12, seed=1) -> dict` — chave mestra conhecida exceto `unknown_bits` iniciais; busca exaustiva com known-plaintext; mede chaves/s, confirma recuperação, extrapola tempo para 2^unknown, 2^56, 2^128, 2^256 (anos). Para `xor-repeating`: espaço 2^32.
- `avalanche(variant, *, samples=500, flip="plaintext"|"key") -> dict` — IV/salt fixos; % de bits alterados (média, desvio, min, max); histograma 0..128.
- `sac_matrix(variant, *, samples=200) -> dict` — matriz 128×128 de P(bit_out muda | bit_in muda); desvio médio de 0.5.
- `statistics(variant, plaintext: bytes) -> dict` — histograma 256, χ² vs uniforme + p-valor (`scipy.stats.chi2`), entropia Shannon (bits/byte), correlação serial, blocos de 16 B repetidos.
- `frequency_attack_xor(ciphertext, key_len_max=8) -> dict` — estima tamanho da chave (índice de coincidência) e recupera chave por pontuação de frequência do português; retorna `recovered_key`, `plaintext_preview`, `success`.
- `ecb_image_leak(variant_names) -> dict[name -> PIL.Image]` — cifra os pixels de uma imagem sintética com logotipo (áreas uniformes) e renderiza o ciphertext como imagem (efeito "pinguim do ECB").

**`experiments.py`:** `run_all(store, out_dir: Path, *, quick=False) -> dict` — roda tudo para todas as variantes, salva `results.json` + PNGs em `out_dir`, registra eventos `crypto.*`, e responde as 4 perguntas da Parte 4 em `results["conclusions"]` derivadas dos números (ex.: avalanche ok se média ∈ [45%,55%]).

- [ ] Testes (`quick=True`): `sbx-10r-cbc` avalanche plaintext média ∈ [0.45,0.55]; `sbx-1r-ecb` avalanche plaintext < 0.15; `xor-repeating` avalanche < 0.02; `frequency_attack_xor` recupera chave de texto PT ≥ 600 chars; χ² p-valor de `sbx-10r-cbc` sobre texto repetitivo > 0.001 e de `xor-repeating` < 1e-6; brute force com 8 bits recupera a chave; ECB repete blocos em plaintext padronizado, CBC não; `run_all(quick=True)` cria `results.json` com chaves `brute_force, avalanche, sac, statistics, frequency_attack, conclusions`.
- [ ] FAIL → implementar → PASS → commit `feat(cryptolab): simulate brute force, differential and statistical attacks`.

### Task 7: Feedback P1 — chave por finalidade e por conversa nas mensagens privadas

**Files:**
- Modify: `common/message_crypto.py`
- Test: `tests/test_message_crypto.py` (adicionar casos)

**Design:** `MESSAGE_CRYPTO_VERSION = 2`; `conversation_key(master, sender_id, recipient_id) -> bytes` = HKDF-SHA256(master, salt=None, info=`b"secureboard:message:v2:conv:" + f"{min}:{max}"`). `encrypt_message` usa v2. `decrypt_message` aceita v1 (chave mestra direta, legado) e v2. Chave mestra nunca cifra dado diretamente na v2.

- [ ] Testes: nova mensagem retorna versão 2; v2 da conversa (1,2) não decifra com chave derivada da conversa (1,3); conversation_key simétrica (1,2)==(2,1); ciphertext v1 gerado manualmente com chave mestra ainda decifra; versão 3 → `MessageDecryptionError`. Ajustar testes existentes que fixam versão 1.
- [ ] Rodar suíte de mensagens → PASS; commit `feat(messages): derive per-conversation keys from master key`.

### Task 8: Dashboard admin + CLI

**Files:**
- Create: `apps/cryptolab/__init__.py`, `apps/cryptolab/routes.py`, `apps/cryptolab/templates/cryptolab_dashboard.html`, `apps/cryptolab/templates/cryptolab_stego.html`, `apps/cryptolab/charts.py`, `static/css/cryptolab.css`, `cryptolab/config.py`
- Modify: `run.py` (registrar blueprint, config `CRYPTOLAB_DIR=data/cryptolab`, `CRYPTOLAB_MASTER_KEYS` env), `apps/root/templates/base_admin.html` (link), `.gitignore` (`data/cryptolab/`)
- Test: `tests/test_cryptolab_dashboard.py`

**Interfaces:**
- `charts.py`: `bar_chart(values, labels, *, width, height, title) -> Markup` (SVG, sem style inline), `line_chart(series, ...) -> Markup`, `heatmap(matrix, ...) -> Markup`.
- Rotas (todas `_require_admin`, POST com `@csrf_protect`): `GET /admin/cryptolab` (KPIs, tabela de ataques, avalanche, histogramas, timeline de eventos/anomalias, alertas top-N, imagens ECB, conclusões; estado vazio se não há `results.json`); `GET /admin/cryptolab/img/<name>` (whitelist de PNG gerados); `GET|POST /admin/cryptolab/stego` (texto + PNG → baixar stego PNG; extrair: PNG → texto ou erro registrado como `crypto.decrypt.failure`); `POST /admin/cryptolab/run` (roda `run_all(quick=True)` + `detect`).
- CLI (`flask --app run …`): `cryptolab-genkey`, `cryptolab-simulate --events N`, `cryptolab-ingest`, `cryptolab-detect`, `cryptolab-experiments [--quick]`, `cryptolab-all`.
- Uso do dashboard registra eventos reais no EventStore.

- [ ] Testes: anônimo → redirect /login; usuário comum → 403 em todas as rotas; admin sem dados → 200 com texto de estado vazio; admin após `run_all(quick)` → 200 contendo "Efeito avalanche" e `<svg`; stego POST sem CSRF → 403; stego round-trip via test client devolve o segredo; nome de imagem fora da whitelist → 404.
- [ ] FAIL → implementar → PASS → suíte completa sem novas falhas → commit `feat(cryptolab): add admin security dashboard and cli`.

### Task 9: Execução completa, evidências, relatório, slides e registro de IA

**Files:**
- Create: `docs/projeto2/README.md` (como rodar), `docs/projeto2/relatorio.html` → `relatorio.pdf`, `docs/projeto2/slides.html` → `slides.pdf`, `docs/projeto2/registro-uso-ia.md`, `docs/projeto2/evidencias/` (results.json, PNGs, prints do dashboard via Chrome headless)
- Modify: `README.md` (seção CryptoLab)

- [ ] `flask cryptolab-all` com 1.000.000 eventos; anotar tempos e métricas reais.
- [ ] Subir app local, capturar screenshots (Chrome headless com cookie de admin de demonstração) do dashboard e stego.
- [ ] Relatório (6–10 pág.): algoritmo, funcionamento, chaves (KeyRing/HKDF/rotação — resposta ao feedback), esteganografia, Big Data, IA, testes, resultados com números do `results.json`, respostas às 4 perguntas, análise crítica, conclusão, referências. Slides ~12.
- [ ] Gerar PDFs com Chrome headless; conferir visualmente páginas.
- [ ] Commit `docs: add projeto 2 report, slides and evidence`.

### Task 10: Revisão final

- [ ] Suíte completa: mesmas 4 falhas ambientais e nada mais.
- [ ] Checklist de requisitos do PDF ↔ evidência (tabela no README do projeto 2).
- [ ] Revisão do branch inteiro por um revisor independente; corrigir achados.
