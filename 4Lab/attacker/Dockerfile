FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    dnsutils \
    bind9 \
    tcpdump \
    scapy \
    hping3 \
    nmap \
    vim \
    net-tools \
    iputils-ping \
    iproute2 \
    iptables \
    ettercap-text-only \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install scapy dnspython

COPY dns_spoof.py /root/
COPY fake_mail_server.py /root/

CMD ["/bin/bash"]
