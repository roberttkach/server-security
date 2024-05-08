#!/bin/bash

if ! command -v openssl &> /dev/null
then
    echo "openssl not found, installing..."
    sudo apt-get install openssl -y
fi

HOST=$1
PORT=$2

END_DATE=$(echo | openssl s_client -servername "$HOST" -connect "$HOST":"$PORT" 2>/dev/null | openssl x509 -noout -enddate | cut -d "=" -f 2)

if [ $? -ne 0 ]; then
    echo "Error getting certificate expiration date"
    exit 2
fi

END_DATE_TS=$(date -d "$END_DATE" +%s 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "Error converting certificate expiration date"
    exit 2
fi

CURRENT_TS=$(date +%s 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "Error getting current date"
    exit 2
fi

if [ "$CURRENT_TS" -gt "$END_DATE_TS" ]; then
    echo "Detected expired SSL/TLS certificates"
    exit 1
else
    echo "SSL/TLS certificates are valid"
    exit 0
fi
