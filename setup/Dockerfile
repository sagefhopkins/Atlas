FROM python:3.11-alpine

RUN apk update && apk add --no-cache \
    build-base \
    libffi-dev \
    openssl-dev \
    libpcap-dev \
    tcpdump \
    libnet \
    libusb \
    py3-pip \
    bash \
    iproute2 \
    iputils \
    && pip install --no-cache-dir scapy fastapi uvicorn redis

    WORKDIR /app
    COPY backend /app/backend
    COPY setup /app/setup

    CMD ["uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8000"]