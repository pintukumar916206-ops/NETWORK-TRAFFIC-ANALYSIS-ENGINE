# --- Stage 1: Build the C++ Engine ---
FROM gcc:latest AS builder
RUN apt-get update && apt-get install -y cmake make libpcap-dev
WORKDIR /app
COPY . .
RUN mkdir -p build && cd build && cmake .. && make -j$(nproc)

# --- Stage 2: Final Runtime (Python + Engine) ---
FROM python:3.9-slim
WORKDIR /app

# Install runtime dependencies for both Python and C++
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libcap2-bin \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy everything from project
COPY . .

# Copy the compiled engine from the builder stage
COPY --from=builder /app/build/traffic_engine /app/traffic_engine

# Ensure permissions and directories
RUN chmod +x /app/traffic_engine && mkdir -p uploads

# Environment Variables for manual setup
ENV ANALYZER_BIN=/app/traffic_engine
ENV UPLOAD_FOLDER=/app/uploads
ENV PORT=5000

EXPOSE 5000

# Start the dashboard with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "scripts.dashboard:app"]
