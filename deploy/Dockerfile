FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY deaddrop/ /app/deaddrop/

ENV DEADDROP_BLOB_DIR=/app/blob_storage
ENV DEADDROP_DB_PATH=/app/data/deaddrop.db

RUN mkdir -p /app/blob_storage /app/data

EXPOSE 8000

CMD ["uvicorn", "deaddrop.server.main:app", "--host", "0.0.0.0", "--port", "8000"]
