FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    libpcap-dev \
    tcpdump \
    libnet1-dev \
    libusb-1.0-0-dev \
    iproute2 \
    iputils-ping \
    git \
    curl \
    bash \
 && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/p0f/p0f.git /opt/p0f && \
    cd /opt/p0f && \
    ./build.sh && make && \
    cp /opt/p0f/p0f /usr/bin/p0f

RUN pip install --no-cache-dir scapy fastapi uvicorn redis pyp0f

WORKDIR /app

COPY backend /app/backend
COPY setup /app/setup

CMD ["uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8000"]
