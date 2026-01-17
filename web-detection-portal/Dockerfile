FROM python:3.11-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app/web

# Copy project files
COPY . .

# Install dependencies
RUN uv sync --frozen --no-dev

# Expose correct port
EXPOSE 3003

ENV FLASK_APP=app.py
ENV FLASK_ENV=production

CMD ["uv", "run", "python", "app.py"]
