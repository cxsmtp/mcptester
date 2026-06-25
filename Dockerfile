# FIX (vulnerable base image): use a current, maintained, minimal base instead of EOL python:3.6.
FROM python:3.12-slim

# FIX (KICS Passwords And Secrets): no secrets baked into the image. Secrets are
# supplied at runtime via the orchestrator's secret store / environment.

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# FIX (KICS Missing User Instruction): create and switch to a non-root user.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

ENV BIND_HOST=0.0.0.0 \
    FLASK_DEBUG=false

EXPOSE 5000

# FIX (missing healthcheck): basic liveness probe.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/token')" || exit 1

CMD ["python", "app.py"]
