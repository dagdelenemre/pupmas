# PUPMAS - Dockerfile
FROM kalilinux/kali-rolling:latest

LABEL maintainer="PUPMAS Team"
LABEL description="PUPMAS - Advanced Cybersecurity Operations Framework"

# Update and install dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    nmap \
    masscan \
    dnsutils \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /opt/pupmas

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create data directories
RUN mkdir -p data/logs data/reports data/templates data/schemas

# Install PUPMAS
RUN python3 setup.py install

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PUPMAS_HOME=/opt/pupmas

# Default command
CMD ["python3", "pupmas.py", "--mode", "tui"]
