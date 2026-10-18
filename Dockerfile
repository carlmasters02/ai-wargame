# AI Wargame — single-container deployment.
# Build:  docker build -t ai-wargame .
# Run:    docker run -p 127.0.0.1:8000:8000 --env-file .env ai-wargame
# Exposed: add -e WARGAME_TOKEN=<long random secret>, then open http://host:8000/#token=<secret>
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static
COPY data ./data
COPY replays/golden.jsonl ./replays/golden.jsonl
COPY benchmarks ./benchmarks

RUN useradd --create-home wargame && chown -R wargame /app
USER wargame

EXPOSE 8000
# Bound to all interfaces inside the container. Without WARGAME_TOKEN the app only
# answers requests addressed to localhost, so set one before exposing it.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
