#!/bin/bash

echo "=== Starting Mail Server Setup ==="

# Create TrustedHosts file
cat > /etc/opendkim/TrustedHosts << ENDEOF
127.0.0.1
localhost
172.20.0.0/16
*.example.com
ENDEOF

# Ensure directory exists and has correct permissions
mkdir -p /etc/opendkim/keys/example.com
chown -R opendkim:opendkim /etc/opendkim

# Generate DKIM keys if they don't exist
if [ ! -f /etc/opendkim/keys/example.com/default.private ]; then
    echo "Generating DKIM keys..."
    cd /etc/opendkim/keys/example.com
    opendkim-genkey -b 2048 -d example.com -s default -v
    chown opendkim:opendkim default.private default.txt
    chmod 600 default.private
    
    echo "DKIM public key:"
    cat default.txt
fi

# Create log file if it doesn't exist
touch /var/log/mail.log
chmod 666 /var/log/mail.log

echo "Starting rsyslog..."
/usr/sbin/rsyslogd -n &

sleep 1

echo "Starting OpenDKIM..."
/usr/sbin/opendkim -u opendkim -p inet:8891@localhost &

sleep 1

echo "Starting Postfix..."
/usr/lib/postfix/sbin/master -c /etc/postfix &

sleep 2

echo "=== Mail Server Started ==="
echo "Services running:"
ps aux | grep -E 'postfix|opendkim|rsyslog' | grep -v grep

# Keep container running
tail -f /var/log/mail.log
