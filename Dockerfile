FROM python:3.13.7-slim

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

RUN addgroup --system wiwgroup && adduser --system --ingroup wiwgroup wiwuser

WORKDIR /app

COPY pyproject.toml .

RUN pip install --no-cache-dir .

ENV PYTHONPATH=/app

COPY . .

EXPOSE 8080

ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=8080

RUN chown -R wiwuser:wiwgroup /app
USER wiwuser

CMD ["python", "app.py"]
