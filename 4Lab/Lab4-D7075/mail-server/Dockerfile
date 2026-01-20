FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Configure Postfix BEFORE installation
RUN echo "postfix postfix/mailname string example.com" | debconf-set-selections && \
    echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections

RUN apt-get update && apt-get install -y \
    postfix \
    opendkim \
    opendkim-tools \
    mailutils \
    rsyslog \
    telnet \
    dnsutils \
    vim \
    tcpdump \
    net-tools \
    swaks \
    && rm -rf /var/lib/apt/lists/*

# Note: Configuration files are mounted via volume from ./config directory

RUN mkdir -p /etc/opendkim/keys/example.com && \
    chown -R opendkim:opendkim /etc/opendkim

COPY opendkim.conf /etc/opendkim.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 25 587 993

ENTRYPOINT ["/entrypoint.sh"]
