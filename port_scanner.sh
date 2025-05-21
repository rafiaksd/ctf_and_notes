#!/bin/bash

TARGET="10.10.11.70"
PORTS=$(seq 1 65536)  
CONCURRENCY=252       # Number of parallel threads
CURL_TIMEOUT=3       

scan_port() {
    PORT=$1

    if (( PORT % 500 == 0 )); then
        echo "Scanning port $PORT..."
    fi
    
    if curl -s -o /dev/null -I --max-time "$CURL_TIMEOUT" --connect-timeout "$CURL_TIMEOUT" "http://$TARGET:$PORT" &>/dev/null; then
        echo "PORT $PORT WORKED"
        curl --max-time "$CURL_TIMEOUT" "http://$TARGET:$PORT" > "curl_response_$PORT.log" 2>&1
    fi

    # No action if curl fails
}

# Export function/variables for parallel
export -f scan_port
export TARGET CURL_TIMEOUT

echo "Starting port scan on $TARGET for ports 1-65536 (timeout: ${CURL_TIMEOUT}s, concurrency: ${CONCURRENCY})..."
echo "$PORTS" | parallel -j "$CONCURRENCY" scan_port

echo "Scan complete. Check files named 'curl_response_*.log' for successful connections."
