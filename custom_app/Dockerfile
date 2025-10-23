# Use the official lightweight Python image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && \
    apt-get install -y netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Copy the rest of the application code
COPY . .

# Expose the port Flask runs on
EXPOSE 5000

# Run the application using Gunicorn with the eventlet worker for SocketIO.
# Reverting to the stable exec form of CMD, removing the problematic --no-preload flag.
# CMD ["gunicorn", "--worker-class", "eventlet", "w", "1", "--bind", "0.0.0.0:5000", "app:socketio_app"]
