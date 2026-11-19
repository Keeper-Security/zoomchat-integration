# Keeper Zoom App Dockerfile
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    ZOOM_CONFIG_PATH=/app/config/zoom_config.yaml

# Copy requirements first
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY run_zoom.py .

# Non-root user; logs and state are written to mounted volumes
RUN useradd --create-home --uid 1000 keeper \
    && mkdir -p /app/logs /app/data /app/config \
    && chown -R keeper:keeper /app
USER keeper

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://localhost:3000/health', timeout=3).status == 200 else 1)"

CMD ["python", "run_zoom.py"]
