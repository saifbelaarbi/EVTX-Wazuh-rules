FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir ".[dev]" requests && \
    chmod +x docker-entrypoint.sh

CMD ["sh", "docker-entrypoint.sh"]
