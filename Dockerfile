# Pin the official release. Override only when intentionally validating an upgrade.
ARG ZEEK_IMAGE=zeek/zeek:9.0.0
FROM ${ZEEK_IMAGE}

USER root
# The pinned official image already provides Python 3.13 and tzdata.
# Verify dependencies rather than adding a network-dependent apt install.
RUN python3 -c 'import sys; from zoneinfo import ZoneInfo; assert sys.version_info >= (3, 11); ZoneInfo("UTC"); ZoneInfo("Asia/Shanghai")'

WORKDIR /opt/zeek-monitor
COPY src/ ./src/
COPY zeek/ ./zeek/
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=UTC \
    CAPTURE_INTERFACE=eth0 \
    LOG_FILE=/dev/stdout
STOPSIGNAL SIGTERM
ENTRYPOINT ["python3", "/opt/zeek-monitor/src/entrypoint.py"]
