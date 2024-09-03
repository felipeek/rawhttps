#!/bin/bash
docker build . -t rawhttps
docker run --platform linux/amd64 -v ~/Development/openssl_certificate_generation/local-deployer/client1.crt:/usr/src/app/cert.crt -v ~/Development/openssl_certificate_generation/local-deployer/client1.key:/usr/src/app/cert.key -p 8080:8080 rawhttps
