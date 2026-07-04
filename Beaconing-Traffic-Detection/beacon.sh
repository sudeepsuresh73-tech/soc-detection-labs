#!/bin/bash
while true; do
    echo "BEACON $(date) $(hostname)" | nc -w 1 192.168.56.103 8080
    sleep 30
done
