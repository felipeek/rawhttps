SRC=../../src/tls/crypto
BIN=../../bin/src/tls/crypto

build: project
	gcc -g -o asn1_test asn1_test.c -I../../include -I$(SRC) $(BIN)/hobig.o $(BIN)/random.o $(BIN)/arith.o $(BIN)/asn1.o 

run:
	@./asn1_test
project:
	$(MAKE) --no-print-directory -C ../../