# SecureBoard AI

O SecureBoard AI é uma aplicação local de comunidade para publicar discussões, responder a tópicos e trocar mensagens entre participantes.

## Funcionalidades

- cadastro e entrada com usuário e senha;
- perfis, biografia, avatar e avatar padrão;
- papéis de usuário e administrador;
- criação, resposta, busca e leitura de discussões;
- mensagens privadas entre usuários;
- painel de administração para moderar discussões e respostas.

## Requisitos

- Python 3.12.x. O fluxo local foi validado com Python 3.12.1;
- Docker é opcional. A imagem usa `python:3.13-slim`.

## Execução local

No Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
flask --app run init-db
flask --app run create-admin
python run.py
```

No macOS ou Linux, ative o ambiente com `source .venv/bin/activate` após criar o virtualenv e execute os mesmos comandos seguintes. `create-admin` solicita usuário, e-mail fictício e senha de forma interativa; a senha fica oculta e não deve ser incluída em argumentos ou arquivos.

Para adicionar dados de demonstração opcionais, depois de `init-db` execute:

```text
flask --app run seed-demo
```

Esse comando solicita interativamente uma senha para os membros de demonstração. A aplicação local inicia na porta `1337`.

Na execução local, o banco padrão fica em `data/secureboard.db` e os avatares em `static/img/avatars`; mantenha esses caminhos para preservar os dados entre inicializações.

## Docker

Construa a imagem:

```text
docker build -t secureboard-ai:baseline .
docker volume create secureboard-data
docker volume create secureboard-avatars
```

Inicialize o banco e crie o administrador usando os volumes persistentes:

```text
docker run --rm -it -v secureboard-data:/app/data -v secureboard-avatars:/app/static/img/avatars secureboard-ai:baseline flask --app run init-db
docker run --rm -it -v secureboard-data:/app/data -v secureboard-avatars:/app/static/img/avatars secureboard-ai:baseline flask --app run create-admin
```

Opcionalmente, adicione os dados de demonstração:

```text
docker run --rm -it -v secureboard-data:/app/data -v secureboard-avatars:/app/static/img/avatars secureboard-ai:baseline flask --app run seed-demo
```

Inicie a aplicação publicando somente na interface local:

```text
docker run --name secureboard-ai -p 127.0.0.1:1337:1337 -v secureboard-data:/app/data -v secureboard-avatars:/app/static/img/avatars secureboard-ai:baseline
```

O banco em `/app/data/secureboard.db` e os avatares em `/app/static/img/avatars` permanecem nos dois volumes nomeados. Para recriar o contêiner com os mesmos volumes, execute `docker stop secureboard-ai` e depois `docker rm secureboard-ai`; em seguida, repita o comando `docker run` acima.

Esta configuração é para execução local. Não publique a aplicação em uma rede pública.

## Licenças e avisos

Consulte [LICENSE](LICENSE) para a licença distribuída com o projeto.
