FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/geareye

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --system geareye \
    && useradd --system --gid geareye --home-dir /nonexistent geareye \
    && mkdir -p /data \
    && chown geareye:geareye /data

COPY Backend ./Backend
COPY Frontend ./Frontend
COPY Docs ./Docs

USER geareye
EXPOSE 8000

CMD ["uvicorn", "Backend.GearEye:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
