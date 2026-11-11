# Projeto 2: CryptoLab

Sistema criptográfico com análise de ataques, construído como módulo do SecureBoard AI.

| Entrega | Arquivo |
|---|---|
| Relatório (10 páginas) | [`relatorio.pdf`](relatorio.pdf) (fonte: `relatorio.html`) |
| Slides (12) | [`slides.pdf`](slides.pdf) (fonte: `slides.html`) |
| Registro de uso de IA | [`registro-uso-ia.md`](registro-uso-ia.md) |
| Evidências | [`evidencias/`](evidencias): `results.json`, `detection.json`, prints do dashboard, imagens ECB |
| Código | `cryptolab/` (núcleo), `apps/cryptolab/` (dashboard e CLI), `tests/test_cryptolab_*.py` |

## Como executar

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
flask --app run init-db && flask --app run create-admin

# chave mestra do CryptoLab (vai para o .env, nunca para o git)
flask --app run cryptolab-genkey          # imprime CRYPTOLAB_MASTER_KEYS=1:...

# pipeline completo: 1M eventos → ataques → IA → Parquet (~11 s)
flask --app run cryptolab-all --events 1000000

python run.py   # entrar como admin → Administração → CryptoLab (Projeto 2)
```

Comandos individuais: `cryptolab-simulate`, `cryptolab-ingest` (importa os `security_events` reais, pseudonimizados), `cryptolab-detect` e `cryptolab-experiments [--quick]`. Os dados gerados ficam em `data/cryptolab/`, que está no `.gitignore`.

Testes: `python -m unittest discover -s tests`. São 89 testes novos. As 4 falhas que aparecem já existiam antes deste trabalho e dependem do ambiente: o banco padrão `data/secureboard.db` existe localmente e o macOS resolve `/var` como symlink de `/private/var`.

## Requisitos do enunciado × evidência

| Requisito (Aula 26) | Evidência |
|---|---|
| Criptografia simétrica com geração dinâmica de chaves | `cryptolab/keys.py`, `cryptolab/cipher.py`; relatório §02 |
| Chave influencia a cifragem e não é fixa | Avalanche de chave de 49,91%; `test_same_message_encrypts_differently` |
| XOR, substituição, permutação, blocos, difusão e confusão | Rodada da SBX-128; SAC por rodadas (§03) |
| Esteganografia em imagens | `/admin/cryptolab/stego`; `evidencias/stego_*.png` |
| Big Data (logs cripto, autenticação, anomalias, padrões, grandes volumes) | DuckDB com 1M de eventos; `evidencias/07_bigdata.png` |
| IA para comportamentos anormais | Isolation Forest + híbrido; `evidencias/detection.json` |
| Força bruta, diferencial e estatístico | `cryptolab/attacks.py`; `evidencias/results.json` |
| Avalanche, distribuição estatística e resistência | Relatório §03 e §05 |
| Dashboard de ataques, anomalias e resultados | `/admin/cryptolab`; `evidencias/dashboard_completo.png` |
| Respostas da Parte 4 | Relatório §05; slide 12; seção "Conclusões" do dashboard |
| Feedback P1: chave única | Mensagens privadas v2 com chave por conversa (`common/message_crypto.py`) |
