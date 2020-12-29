#!/bin/bash

echo "******"
echo "Making a new self-signed certificate."
echo "Use any password for the key, it will be stripped."
echo "When prompted for common name, give the hostname where the server will run (e.g. localhost)"
echo "******"

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650
openssl rsa -in key.pem -out key-plain.pem
