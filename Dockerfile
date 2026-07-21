FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app app
COPY demo.py .

# Data and outbox live on the container's ephemeral disk. That's fine here --
# the app seeds itself on first boot if the DB is empty, so a restart just
# gets you a fresh copy of the four demo scenarios instead of losing anything
# that matters.
RUN mkdir -p data outbox

EXPOSE 8000

# Render/HF Spaces/Railway all inject $PORT; default to 8000 for a plain
# `docker run` locally.
CMD ["sh", "-c", "uvicorn app.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
