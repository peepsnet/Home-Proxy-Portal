FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PORTAL_CONFIG=/data/config.json
RUN useradd -r -u 10001 portal && mkdir /data && chown portal /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY portal.py .
USER portal
VOLUME /data
EXPOSE 8443
CMD ["python", "portal.py"]
