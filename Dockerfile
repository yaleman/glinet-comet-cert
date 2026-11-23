FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY uploader.py /app/uploader.py
USER 65532:65532
ENTRYPOINT ["python3", "/app/uploader.py"]
