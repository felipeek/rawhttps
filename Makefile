CC = gcc
CFLAGS = -Wall -Iinclude -g -m64
LDFLAGS= -lpthread

# Final binary
BIN = ssltests
# Put all auto generated stuff to this build dir.
BUILD_DIR = ./bin

# List of all .c source files.
C = $(wildcard ./src/*.c) $(wildcard ./src/http/*.c)
ASM = $(wildcard ./src/*.asm)

# All .o files go to build dir.
OBJ = $(C:%.c=$(BUILD_DIR)/%.o) $(ASM:%.asm=$(BUILD_DIR)/%.o)
# Gcc/Clang will create these .d files containing dependencies.
DEP = $(OBJ:%.o=%.d)

# Default target named after the binary.
$(BIN) : $(BUILD_DIR)/$(BIN)

# Actual target of the binary - depends on all .o files.
$(BUILD_DIR)/$(BIN) : $(OBJ)
	# Create build directories - same structure as sources.
	mkdir -p $(@D)
	# Just link all the object files.
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

# Build target for every single object file.
$(BUILD_DIR)/%.o : %.asm
	mkdir -p $(@D)
	# The -MMD flags additionaly creates a .d file with
	# the same name as the .o file.
	nasm -felf64 $< -o $@

# Include all .d files
-include $(DEP)

# Build target for every single object file.
# The potential dependency on header files is covered
# by calling `-include $(DEP)`.
$(BUILD_DIR)/%.o : %.c
	mkdir -p $(@D)
	# The -MMD flags additionaly creates a .d file with
	# the same name as the .o file.
	$(CC) $(CFLAGS) -MMD -c $< -o $@

.PHONY : clean
clean :
	# This should remove all generated files.
	-rm $(BUILD_DIR)/$(BIN) $(OBJ) $(DEP)
