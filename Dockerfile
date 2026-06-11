# --- BUILDER ---
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /application

COPY pyproject.toml poetry.lock ./

ENV POETRY_VERSION=2.3.2
RUN pip3 install --upgrade pip setuptools wheel --break-system-packages
RUN pip3 install "poetry==$POETRY_VERSION"

RUN poetry config virtualenvs.in-project true && \
    poetry install --only main --no-root

# --- RUNTIME ---
FROM python:3.12-slim

RUN addgroup --system wiwgroup && adduser --system --ingroup wiwgroup wiwuser

##Configure timezone
RUN ln -fs /usr/share/zoneinfo/Europe/Rome /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

WORKDIR /application

COPY --from=builder /application/.venv ./.venv
COPY app/ ./app
COPY *.py ./

RUN chown -R wiwuser:wiwgroup ./app
RUN chown wiwuser:wiwgroup ./*.py


ENV PATH="/application/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    TZ=Europe/Rome \
    FLASK_RUN_HOST=0.0.0.0 \
    FLASK_RUN_PORT=8080

EXPOSE $FLASK_RUN_PORT

USER wiwuser

CMD ["python", "run.py"]
