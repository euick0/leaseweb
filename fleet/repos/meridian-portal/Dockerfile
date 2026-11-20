# Installs only the vendored wheels in wheels/. No index, no network.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
COPY wheels/ wheels/
RUN pip install --no-cache-dir --no-index --find-links wheels -r requirements.txt
COPY app.py .
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python", "app.py"]
