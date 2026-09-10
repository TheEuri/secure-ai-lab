
FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY apps/ ./apps/
COPY common/ ./common/
COPY data/avatars/ ./data/avatars/
COPY static/css/bootstrap.min.css static/css/app.css static/css/navbar.css static/css/404.css ./static/css/
COPY static/img/favicon.ico ./static/img/
COPY static/js/bootstrap.bundle.min.js ./static/js/
COPY static/robots.txt ./static/
COPY templates/ ./templates/
COPY LICENSE NOTICE run.py ./

VOLUME ["/app/data", "/app/static/img/avatars"]

EXPOSE 1337

ENV FLASK_APP=run.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=development

CMD ["flask", "run", "--host=0.0.0.0", "--port=1337"]
