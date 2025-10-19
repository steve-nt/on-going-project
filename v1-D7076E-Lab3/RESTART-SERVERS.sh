#!/bin/bash
# Restart servers with updated configuration

echo "=== Restarting Servers with Updated Code ==="
echo ""

# Stop old processes
echo "Stopping old processes..."
pkill -f "PersonB-integrated_app.py"
pkill -f "PersonB-mitm_proxy.py"
sleep 2

echo "Processes stopped."
echo ""

# Check if ports are free
echo "Checking ports..."
PORT5000=$(lsof -ti:5000)
PORT8080=$(lsof -ti:8080)

if [ -n "$PORT5000" ]; then
    echo "Warning: Port 5000 still in use by PID $PORT5000"
    echo "Run: kill $PORT5000"
fi

if [ -n "$PORT8080" ]; then
    echo "Warning: Port 8080 still in use by PID $PORT8080"
    echo "Run: kill $PORT8080"
fi

if [ -z "$PORT5000" ] && [ -z "$PORT8080" ]; then
    echo "✓ Ports 5000 and 8080 are free"
fi

echo ""
echo "To start servers:"
echo ""
echo "Terminal 1:"
echo "  cd /home/steven/Desktop/on-going-project/v1-D7076E-Lab3"
echo "  python3 PersonB-integrated_app.py"
echo ""
echo "Terminal 2:"
echo "  cd /home/steven/Desktop/on-going-project/v1-D7076E-Lab3"
echo "  python3 PersonB-mitm_proxy.py"
echo ""
echo "Terminal 3 (testing):"
echo "  cd /home/steven/Desktop/on-going-project/v1-D7076E-Lab3"
echo "  ./test_mitm_complete.sh"
echo ""
