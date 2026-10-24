#!/bin/bash
# Forward localhost ports to Windows Burp Pro (WSL → Windows host)
# Run this when Burp Pro is active on Windows.
# Usage: bash burp-forward.sh [start|stop|status]

WIN_HOST=$(ip route show default | awk '{print $3}' | head -1)
MCP_PORT=9876
PROXY_PORT=8080

case "${1:-start}" in
  start)
    fuser -k $MCP_PORT/tcp 2>/dev/null
    fuser -k $PROXY_PORT/tcp 2>/dev/null
    ncat -lk 127.0.0.1 $MCP_PORT -c "ncat $WIN_HOST $MCP_PORT" &
    ncat -lk 127.0.0.1 $PROXY_PORT -c "ncat $WIN_HOST $PROXY_PORT" &
    sleep 1
    echo "Forwarding 127.0.0.1:$MCP_PORT → $WIN_HOST:$MCP_PORT (Burp MCP)"
    echo "Forwarding 127.0.0.1:$PROXY_PORT → $WIN_HOST:$PROXY_PORT (Burp Proxy)"
    curl -s --max-time 2 http://127.0.0.1:$MCP_PORT/ -o /dev/null -w "MCP: HTTP %{http_code}\n"
    curl -s --max-time 2 http://127.0.0.1:$PROXY_PORT/ -o /dev/null -w "Proxy: HTTP %{http_code}\n"
    ;;
  stop)
    fuser -k $MCP_PORT/tcp 2>/dev/null
    fuser -k $PROXY_PORT/tcp 2>/dev/null
    echo "Stopped port forwarding."
    ;;
  status)
    echo -n "MCP ($MCP_PORT): "; fuser $MCP_PORT/tcp 2>/dev/null && echo "running" || echo "not running"
    echo -n "Proxy ($PROXY_PORT): "; fuser $PROXY_PORT/tcp 2>/dev/null && echo "running" || echo "not running"
    ;;
esac
