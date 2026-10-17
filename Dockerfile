FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gateway gateway
COPY cli cli
COPY policies policies
RUN useradd -m mandate && mkdir -p /data && chown mandate /data
USER mandate
ENV MANDATE_DATA=/data MANDATE_POLICY_DIR=/app/policies
EXPOSE 8080
CMD ["uvicorn", "gateway.http_api:app", "--host", "0.0.0.0", "--port", "8080"]
