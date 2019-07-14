SRC=../../src
BIN=../../bin

build: project
	gcc -g -o hobig_test hobig_test.c -I../../include -I$(SRC) $(BIN)/src/hobig.o $(BIN)/src/random.o $(BIN)/src/arith.o

run:
	@./hobig_test
project:
	$(MAKE) --no-print-directory -C ../../