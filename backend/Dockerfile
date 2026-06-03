FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ARG SERVICE_DIR
ARG APP_MODULE

ENV APP_MODULE=${APP_MODULE}

COPY ${SERVICE_DIR}/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend

CMD ["sh", "-c", "uvicorn ${APP_MODULE}:app --host 0.0.0.0 --port 8000"]
