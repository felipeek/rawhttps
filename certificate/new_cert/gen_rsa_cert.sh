#!/bin/bash
openssl req -new -key key.pem -out req.pem
openssl req -key key.pem -new -x509 -days 365 -out cert.pem
