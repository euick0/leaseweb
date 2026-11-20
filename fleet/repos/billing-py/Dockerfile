# Installs only the vendored wheels in wheels/. No index, no network.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
COPY wheels/ wheels/
RUN pip install --no-cache-dir --no-index --find-links wheels -r requirements.txt
COPY app.py .
COPY keys/ keys/
# Harmless marker for the safe path-traversal probe (agent/probes.py)
COPY pp-probe/marker.txt /srv/pp-probe/marker.txt
ENV ACME_KEY_DIR=/app/keys PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python", "app.py"]
