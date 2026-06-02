FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir .

CMD ["sh", "-c", "\
    python -m collector download-all && \
    python -m collector download-sigma && \
    python -m collector download-defaults && \
    python -m generator generate --auto-approve && \
    python -m generator convert-sigma --auto-approve --min-level medium && \
    python -m generator validate && \
    python -m generator logtest --mode simulate --save \
"]
