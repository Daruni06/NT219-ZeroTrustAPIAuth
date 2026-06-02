FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY authz/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY authz ./authz

CMD ["uvicorn", "authz.main:app", "--host", "0.0.0.0", "--port", "8090"]
