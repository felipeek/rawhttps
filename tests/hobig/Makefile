SRC=../../src/tls/crypto
BIN=../../bin/src/tls/crypto

build: project
	gcc -DDEBUG_MEMORY -g -o hobig_test hobig_test.c ../../src/tls/crypto/hobig.c -I../../include -I$(SRC) $(BIN)/random.o $(BIN)/arith.o

run:
	@./hobig_test
project:
	$(MAKE) --no-print-directory -C ../../