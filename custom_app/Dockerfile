# Use the official lightweight Python image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file (ensure Flask-SQLAlchemy and psycopg2-binary are listed)
COPY requirements.txt .

# 1. Install system dependencies required for database compilation (libpq-dev) 
# 2. Install Python packages (pip install)
# 3. Clean up development packages (libpq-dev, gcc) and caches to minimize final image size
RUN apt-get update && \
    # Install packages: libpq-dev for psycopg2, gcc for C compilation, netcat for startup script
    apt-get install -y libpq-dev netcat-openbsd gcc && \
    \
    # Install Python dependencies using pip
    pip install --no-cache-dir -r requirements.txt && \
    \
    # Clean up: Remove development packages (gcc, libpq-dev) after they are no longer needed
    apt-get remove -y gcc libpq-dev && \
    apt-get autoremove -y && \
    \
    # Clean up apt lists
    rm -rf /var/lib/apt/lists/*

# Copy the rest of the application code
COPY . .

# Expose the port Flask runs on
EXPOSE 5000

# The CMD used for your Gunicorn/SocketIO application
CMD ["gunicorn", "--worker-class", "eventlet", "--workers", "1", "--bind", "0.0.0.0:5000", "app:socketio_app"]
