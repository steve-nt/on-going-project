#!/bin/bash
# Complete MITM Testing Script
# Tests the full workflow: register -> enroll MFA -> login -> verify OTP

echo "=== MITM Proxy Complete Test ==="
echo "This script assumes:"
echo "  - PersonB-integrated_app.py running on port 5000"
echo "  - PersonB-mitm_proxy.py running on port 8080"
echo ""

PROXY_URL="http://localhost:8080"
TEST_USER="testuser_mitm"
TEST_PASS="password123"

echo "============================================"
echo "Step 1: Register new user through proxy"
echo "============================================"
curl -X POST ${PROXY_URL}/register \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"hash_type\":\"bcrypt\"}"
echo -e "\n"

sleep 1

echo "============================================"
echo "Step 2: Enroll user for TOTP MFA through proxy"
echo "============================================"
ENROLL_RESPONSE=$(curl -s -X POST ${PROXY_URL}/mfa/enroll/totp \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USER}\"}")

echo "$ENROLL_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$ENROLL_RESPONSE"
echo -e "\n"

# Extract TOTP secret
TOTP_SECRET=$(echo "$ENROLL_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('secret', ''))" 2>/dev/null)
echo "TOTP Secret extracted: $TOTP_SECRET"
echo ""

sleep 1

echo "============================================"
echo "Step 3: Login through proxy"
echo "============================================"
curl -X POST ${PROXY_URL}/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}"
echo -e "\n"

sleep 1

echo "============================================"
echo "Step 4: Generate and send TOTP token through proxy"
echo "============================================"

if [ -n "$TOTP_SECRET" ]; then
    # Generate TOTP token using Python
    TOTP_TOKEN=$(python3 << EOF
import pyotp
totp = pyotp.TOTP('$TOTP_SECRET')
print(totp.now())
EOF
)
    
    echo "Generated TOTP Token: $TOTP_TOKEN"
    echo ""
    
    echo "Sending TOTP token through MITM proxy..."
    curl -X POST ${PROXY_URL}/mfa/verify \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${TEST_USER}\",\"token\":\"${TOTP_TOKEN}\"}"
    echo -e "\n"
else
    echo "ERROR: Could not extract TOTP secret from enrollment response"
    echo "Skipping TOTP verification test"
fi

sleep 1

echo "============================================"
echo "Step 5: Check captured data"
echo "============================================"
echo "Captured credentials and OTP tokens:"
curl -s ${PROXY_URL}/proxy/captured | python3 -m json.tool
echo ""

sleep 1

echo "============================================"
echo "Step 6: Check proxy statistics"
echo "============================================"
curl -s ${PROXY_URL}/proxy/stats | python3 -m json.tool
echo ""

sleep 1

echo "============================================"
echo "Step 7: Save logs to mitm_logs.json"
echo "============================================"
curl -X POST ${PROXY_URL}/proxy/save
echo -e "\n"

sleep 1

echo "============================================"
echo "Step 8: Display saved logs"
echo "============================================"
if [ -f mitm_logs.json ]; then
    echo "mitm_logs.json contents:"
    cat mitm_logs.json | python3 -m json.tool | head -100
    echo ""
    echo "Full log file saved to: mitm_logs.json"
else
    echo "WARNING: mitm_logs.json not found!"
fi

echo ""
echo "=== Test Complete ==="
echo ""
echo "Summary:"
echo "- Registered user: ${TEST_USER}"
echo "- Enrolled TOTP MFA"
echo "- Captured credentials during login"
echo "- Captured OTP token during MFA verification"
echo "- All data saved to mitm_logs.json"
