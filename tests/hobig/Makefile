SRC=../../src/tls/crypto
BIN=../../bin/src/tls/crypto

build: project
	gcc -g -o hobig_test hobig_test.c -I../../include -I$(SRC) $(BIN)/hobig.o $(BIN)/random.o $(BIN)/arith.o

run:
	@./hobig_test
project:
	$(MAKE) --no-print-directory -C ../../