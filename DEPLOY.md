# Deploy

A aplicação está publicada em **https://act708.pythonanywhere.com**.

Plataforma: PythonAnywhere (plano gratuito). A escolha considerou três requisitos
da aplicação: sistema de arquivos persistente (o banco SQLite em `data/` e os
avatares em `static/img/avatars` precisam sobreviver a reinicializações), acesso
a shell (os comandos `create-admin` e `seed-demo` são interativos) e ausência de
custo. O servidor é o uWSGI da plataforma, que importa `app` diretamente; a
função `run_server()` de `run.py` não é executada neste modo.

## Variáveis de ambiente

A aplicação lê a configuração de um arquivo `.env` na raiz do projeto, carregado
por `run.py` através do `python-dotenv`. **Esse arquivo contém segredos e não faz
parte do repositório** (está coberto pelo `.gitignore` e pelo `.dockerignore`).
Ele precisa ser criado no ambiente de destino.

| Variável | Obrigatória para | Formato |
| --- | --- | --- |
| `MESSAGE_ENCRYPTION_KEY` | mensagens privadas (`/direct`) | Base64URL de exatamente 32 bytes |
| `PSEUDONYMIZATION_KEY` | análise de privacidade (`/admin/privacy-analysis`) | Base64URL de no mínimo 32 bytes |
| `AI_PROVIDER` | moderação por IA | `gemini` |
| `GEMINI_API_KEY` | moderação por IA | chave da API Gemini |
| `GEMINI_MODEL` | moderação por IA | nome de um modelo disponível |
| `AI_TIMEOUT_SECONDS` | opcional | inteiro entre 1 e 60 (padrão 15) |

As duas chaves criptográficas podem ser geradas com:

```bash
python -c 'import secrets,base64;print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))'
```

Sem elas a aplicação **falha fechada**: as funcionalidades correspondentes
retornam HTTP 503 em vez de operar sem proteção criptográfica.

## Procedimento de implantação

```bash
git clone https://github.com/TheEuri/secure-ai-lab.git
cd secure-ai-lab
mkvirtualenv secureboard --python=/usr/bin/python3.12
pip install -r requirements.txt
```

O Python 3.12 é necessário: o `Pillow 10.2.0` fixado em `requirements.txt` não
publica wheel para 3.13, e a instalação cairia em compilação a partir do código-fonte.

Depois de criar o `.env`, inicialize os dados:

```bash
flask --app run init-db
flask --app run create-admin
flask --app run seed-demo
```

Configuração do servidor WSGI:

```python
import os
import sys

project_home = '/home/act708/secure-ai-lab'
if project_home not in sys.path:
    sys.path.insert(0, project_home)
os.chdir(project_home)

from run import app as application
```

## Verificação

Os cabeçalhos de segurança definidos em `common/transport.py` são aplicados em
produção:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; ...
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000
```

A presença do `Strict-Transport-Security` confirma que a plataforma repassa o
esquema HTTPS à aplicação (`request.is_secure` é verdadeiro). Em consequência,
`session_cookie_is_secure()` resolve para verdadeiro e o cookie de sessão é
emitido com a flag `Secure` sem necessidade de configuração adicional.
