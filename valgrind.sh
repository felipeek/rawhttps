#!/bin/bash
valgrind --leak-check=full --dsymutil=yes --track-origins=yes --log-file=valgrind_output ./bin/ssltests ./certificate/other_cert/cert.pem ./certificate/other_cert/key.pem