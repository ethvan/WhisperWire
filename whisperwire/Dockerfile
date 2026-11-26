FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Copy dependency metadata first for better build caching
COPY pyproject.toml uv.lock ./

# Install dependencies without trying to install the project as a package
RUN uv sync --frozen --no-dev --no-install-project

# Copy application source
COPY . .

EXPOSE 8080

CMD ["uv", "run", "--no-sync", "python", "whisperwire.py"]
