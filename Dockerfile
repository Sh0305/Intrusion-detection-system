FROM python:3.11-slim

# Install libpcap for Scapy packet capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default: run the IDS. Override CMD to run the dashboard or train script.
# Requires --cap-add=NET_ADMIN --cap-add=NET_RAW when running.
CMD ["python", "-m", "ids.intrusion"]
