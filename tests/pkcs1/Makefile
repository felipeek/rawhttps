SRC=../../src/tls/crypto
BIN=../../bin/src/tls/crypto

build: project
	gcc -DDEBUG_MEMORY -g -o pkcs1_test pkcs1_test.c ../../src/tls/crypto/pkcs1.c ../../src/tls/crypto/hobig.c -I../../include -I$(SRC) $(BIN)/random.o $(BIN)/arith.o $(BIN)/asn1.o

run:
	@./pkcs1_test
project:
	$(MAKE) --no-print-directory -C ../../