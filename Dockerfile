# AI Wargame — single-container deployment.
# Build:  docker build -t ai-wargame .
# Run:    docker run -p 127.0.0.1:8000:8000 --env-file .env ai-wargame
#         then open the http://localhost:8000/#token=... link printed in the logs.
#         For a fixed token: -e WARGAME_TOKEN=<long random secret>
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
# Traffic reaches a container from the Docker bridge, never from loopback, so the app's
# token-less local mode can't serve it: without WARGAME_TOKEN a random one is generated
# per start and the link to open is printed in the logs (like Jupyter).
CMD ["sh", "-c", "if [ -z \"$WARGAME_TOKEN\" ]; then export WARGAME_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(24))'); echo \"WARGAME_TOKEN not set; generated one for this run. Open http://localhost:8000/#token=$WARGAME_TOKEN\"; fi; exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
