FROM python:3.10-slim

WORKDIR /app

COPY . /app

RUN apt-get update && \
    apt-get install -y libgmp-dev build-essential && \
    pip install --no-cache-dir charm-crypto web3 ipfshttpclient py-solc-x

CMD ["python", "simulate.py"]
