FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    bind9 \
    bind9utils \
    bind9-doc \
    dnsutils \
    vim \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Create all necessary directories
RUN mkdir -p /etc/bind/zones /var/cache/bind /var/lib/bind /run/named

# Copy configuration files
COPY named.conf /etc/bind/
COPY named.conf.options /etc/bind/
COPY named.conf.local /etc/bind/
COPY db.example.com /etc/bind/zones/

# Set ownership and permissions  
RUN chown -R bind:bind /etc/bind /var/lib/bind /var/cache/bind /run/named && \
    chmod -R 755 /etc/bind && \
    chmod -R 775 /var/cache/bind /var/lib/bind /run/named

EXPOSE 53/udp 53/tcp

# Run as bind user
CMD ["named", "-g", "-u", "bind", "-c", "/etc/bind/named.conf"]
