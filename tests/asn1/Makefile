SRC=../../src/tls/crypto
BIN=../../bin/src/tls/crypto

build: project
	gcc -DDEBUG_MEMORY -g -o asn1_test asn1_test.c -I../../include ../../src/tls/crypto/asn1.c ../../src/tls/crypto/hobig.c -I$(SRC) $(BIN)/random.o $(BIN)/arith.o

run:
	@./asn1_test
project:
	$(MAKE) --no-print-directory -C ../../