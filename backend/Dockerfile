FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev gcc g++ curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 analyzer && chown -R analyzer:analyzer /app
# NET_RAW capability is added at runtime via docker-compose cap_add
USER analyzer

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
