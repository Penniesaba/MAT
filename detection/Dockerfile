FROM python:3.13-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app/detection

# Copy project files
COPY . .

# Install dependencies
RUN uv sync --frozen

# Make entrypoint executable
RUN chmod +x docker-entrypoint.sh

# Run entrypoint (checks if results exist, skips if so)
CMD ["./docker-entrypoint.sh"]
