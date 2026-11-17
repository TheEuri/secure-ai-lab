# Projeto 2: CryptoLab

Sistema criptográfico com análise de ataques, construído como módulo do SecureBoard AI.

| Entrega | Arquivo |
|---|---|
| Relatório (8 páginas) | [`relatorio.pdf`](relatorio.pdf) (fonte: `relatorio.html`) |
| Slides (14) | [`slides.pdf`](slides.pdf) (fonte: `slides.html`) |
| Registro de uso de IA | [`registro-uso-ia.md`](registro-uso-ia.md) |
| Evidências | [`evidencias/`](evidencias): `results.json`, `detection.json`, prints do dashboard, integridade (MATCH/MISMATCH), arquivo e imagem adulterados, imagens ECB |
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

# integridade SHA-256 dos arquivos críticos (linha de base assinada por HMAC)
flask --app run cryptolab-integrity        # --reset depois de uma mudança legítima

python run.py   # entrar como admin → Administração → CryptoLab (Projeto 2)
```

Comandos individuais: `cryptolab-simulate`, `cryptolab-ingest` (importa os `security_events` reais, pseudonimizados), `cryptolab-detect` e `cryptolab-experiments [--quick]`. Os dados gerados ficam em `data/cryptolab/`, que está no `.gitignore`.

Testes: `python -m unittest discover -s tests`. São 365 testes (123 novos neste projeto) e todos passam num clone limpo. Se `data/secureboard.db` já existir localmente, 3 testes antigos do Projeto 1 falham de propósito: eles verificam que o banco padrão não foi criado.

## Requisitos do enunciado × evidência

| Requisito (Aula 26) | Evidência |
|---|---|
| Criptografia simétrica com geração dinâmica de chaves | `cryptolab/keys.py`, `cryptolab/cipher.py`; relatório §02 |
| Entrada: texto, arquivos e imagens | `/admin/cryptolab/files` (`cryptolab/files.py`), esteganografia; relatório §01–§02 |
| Chave influencia a cifragem e não é fixa | Avalanche de chave de 49,88%; `test_same_message_encrypts_differently` |
| XOR, substituição, permutação, blocos, difusão e confusão | Rodada da SBX-128; SAC por rodadas (§03) |
| Esteganografia em imagens | `/admin/cryptolab/stego`, ordem dos LSB própria de cada imagem; `evidencias/stego_*.png` |
| Big Data (logs cripto, autenticação, anomalias, padrões, grandes volumes) | DuckDB com 1M de eventos; `evidencias/07_bigdata.png` |
| IA para comportamentos anormais | Isolation Forest + híbrido; `evidencias/detection.json` |
| Anomalia "alterações em arquivos" com dados reais | SHA-256 + linha de base assinada (`cryptolab/integrity.py`); `evidencias/10_integridade_*.png` |
| Força bruta, diferencial e estatístico | `cryptolab/attacks.py`; `evidencias/results.json` |
| Avalanche, distribuição estatística e resistência | Relatório §03 e §05 |
| Dashboard de ataques, anomalias e resultados | `/admin/cryptolab`; `evidencias/dashboard_completo.png` |
| Respostas da Parte 4 | Relatório §05; slide 13; seção "Conclusões" do dashboard |
| Relatório: descrição, funcionamento, testes, resultados, conclusão | Relatório §02, §02, §03–§04, §05, §06 (mapa na capa) |
| Feedback P1: chave única | Chave por mensagem, arquivo, imagem e conversa, separada por finalidade; inventário no relatório §02 |
