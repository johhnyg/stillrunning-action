FROM python:3.11-alpine

RUN apk add --no-cache git curl jq

COPY entrypoint.py /entrypoint.py
RUN chmod +x /entrypoint.py

ENTRYPOINT ["python3", "/entrypoint.py"]
