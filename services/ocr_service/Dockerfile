# AUTHENTIX / EduVerify-AI (SIH26261)
# Python OCR & Document Forensics Microservice Container (Port 8001)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OCR_SERVICE_HOST=0.0.0.0 \
    OCR_SERVICE_PORT=8001

# Install Tesseract OCR (English + Hindi) and Poppler pdftotext for scanned & digital PDFs
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-hin \
    poppler-utils \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash ocruser
WORKDIR /srv/ocr_service

COPY services/ocr_service/server.py /srv/ocr_service/server.py
RUN chown -R ocruser:ocruser /srv/ocr_service

USER ocruser
EXPOSE 8001

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8001/health || exit 1

CMD ["python3", "/srv/ocr_service/server.py"]
