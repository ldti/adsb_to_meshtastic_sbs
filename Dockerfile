# Dockerfile for adsb_to_meshtastic_sbs.py with robust healthcheck and ICAO allocations

ARG PYTHON_VERSION=3.11-slim
FROM python:${PYTHON_VERSION} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install runtime deps
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and ICAO data
COPY adsb_to_meshtastic_sbs.py ./

# Create non-root user
RUN useradd -u 10001 -m appuser
USER appuser

# Environment defaults (override at runtime)
ENV DUMP1090_HOST=10.200.10.18 \
    DUMP1090_PORT=30103 \
    MESHTASTIC_TCP_HOST=10.200.10.16 \
    MESHTASTIC_CHANNEL_INDEX=4 \
    ICAO_ALLOCATIONS_PATH=/app/icao_allocations.json \
    LOG_LEVEL=INFO

# Healthcheck that doesn't require procps/pgrep
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD \
  sh -c 'test -r /proc/1/cmdline && grep -qa "adsb_to_meshtastic_sbs.py" /proc/1/cmdline'

ENTRYPOINT ["python", "-u", "adsb_to_meshtastic_sbs.py"]
