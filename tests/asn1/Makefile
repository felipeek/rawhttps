SRC=../../src
BIN=../../bin

build: project
	gcc -o asn1_test asn1_test.c -I../../include -I$(SRC) $(BIN)/src/hobig.o $(BIN)/src/random.o $(BIN)/src/arith.o $(BIN)/src/asn1.o 

run:
	@./asn1_test
project:
	$(MAKE) --no-print-directory -C ../../