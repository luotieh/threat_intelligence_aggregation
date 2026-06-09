FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir .
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini configs scripts ./
COPY configs ./configs
COPY scripts ./scripts
COPY .env.example ./
RUN mkdir -p /app/release

EXPOSE 18080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "18080"]
