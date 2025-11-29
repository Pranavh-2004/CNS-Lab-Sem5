# Use the official SEED Ubuntu image as the base
FROM handsonsecurity/seed-ubuntu:large-arm

# Update package lists and install gcc and libpcap-dev
# The '-y' flag automatically answers 'yes' to prompts.
# 'rm -rf /var/lib/apt/lists/*' cleans up to reduce image size.
RUN apt-get update && \
    apt-get install -y gcc libpcap-dev && \
    rm -rf /var/lib/apt/lists/*
