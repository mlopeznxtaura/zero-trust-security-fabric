FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    git curl wget gcc libsodium-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

ENTRYPOINT ["python", "main.py"]
CMD ["--mode", "vault", "--action", "bootstrap"]
