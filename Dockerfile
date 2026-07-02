
FROM python:3.12

WORKDIR /app

RUN apt-get update && apt-get install -y tcpdump libpcap-dev iproute2 && rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip install --no-cache-dir \
    flask==2.2.2 \
    werkzeug==2.2.2 \
    scapy==2.5.0 \
    func_timeout \
    flask-cors

EXPOSE 5000

CMD ["python", "main.py"]
