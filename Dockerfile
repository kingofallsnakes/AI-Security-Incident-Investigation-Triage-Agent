FROM python:3.11-slim
WORKDIR /srv/triage
COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --no-cache-dir .
EXPOSE 8000
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]
