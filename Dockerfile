# --- Stage 1: Build the C++ Engine ---
FROM gcc:latest AS builder
RUN apt-get update && apt-get install -y cmake make libpcap-dev
WORKDIR /app
COPY . .
RUN mkdir -p build && cd build && cmake .. && make -j$(nproc) && \
    (cp traffic_engine ../engine_bin 2>/dev/null || cp mock_engine ../engine_bin)

# --- Stage 2: Final Runtime (Python + Engine) ---
FROM python:3.9-slim
WORKDIR /app

# Install runtime dependencies for both Python and C++
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libcap2-bin \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir gunicorn eventlet && \
    pip install --no-cache-dir -r requirements.txt

# Copy necessary files only
COPY scripts/ /app/scripts/
COPY --from=builder /app/engine_bin /app/traffic_engine

# Ensure permissions and directories
RUN chmod +x /app/traffic_engine && mkdir -p uploads

# Environment Variables
ENV ANALYZER_BIN=/app/traffic_engine
ENV UPLOAD_FOLDER=/app/uploads
ENV PORT=5000
ENV FLASK_ENV=production

EXPOSE 5000

# Start with gunicorn and eventlet for SocketIO support
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "scripts.dashboard:app"]
