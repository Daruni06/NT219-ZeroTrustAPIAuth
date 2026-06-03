FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY demo-web/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY demo-web ./demo-web
COPY demo-client ./demo-client

CMD ["uvicorn", "app:app", "--app-dir", "/app/demo-web", "--host", "0.0.0.0", "--port", "8080"]
