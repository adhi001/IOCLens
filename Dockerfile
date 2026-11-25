FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY ioc_lens ./ioc_lens
RUN pip install --no-cache-dir .

EXPOSE 8000
CMD ["uvicorn", "ioc_lens.main:app", "--host", "0.0.0.0", "--port", "8000"]
