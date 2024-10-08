CC = gcc
CFLAGS = -Wall -Iinclude -g -m64
LDFLAGS= -lpthread

# Final binary
BIN = rawhttps.a
# Put all auto generated stuff to this build dir.
BUILD_DIR = ./bin

# List of all .c source files.
C = $(wildcard ./src/*.c) $(wildcard ./src/http/*.c) $(wildcard ./src/tls/*.c) $(wildcard ./src/tls/crypto/*.c)
ASM = $(wildcard ./src/tls/crypto/*.asm)

# All .o files go to build dir.
C_OBJ = $(C:%.c=$(BUILD_DIR)/%.o)
ASM_OBJ = $(ASM:%.asm=$(BUILD_DIR)/%.o)
OBJ = $(C_OBJ) $(ASM_OBJ)
# Gcc/Clang will create these .d files containing dependencies.
DEP = $(C_OBJ:%.o=%.d)

# Detect the operating system
UNAME_S := $(shell uname -s)

# Define architecture; set to x86_64 or arm64 as needed
ARCH = x86_64  # Change this to arm64 if you're targeting Apple Silicon

ifeq ($(UNAME_S), Darwin)
	NASM_FORMAT = macho64  # Use Mach-O format for macOS
	NASM_FLAGS = -D__APPLE__  # Define __APPLE__ for macOS
	CFLAGS += -arch $(ARCH)  # Ensure GCC/Clang target the correct architecture
else
	NASM_FORMAT = elf64    # Use ELF format for Linux
	NASM_FLAGS =           # No additional flags for Linux
	NASM_FLAGS =           # No additional flags for Linux
	CFLAGS += -m64  # Default to 64-bit on Linux
endif

# Default target named after the binary.
$(BIN) : $(BUILD_DIR)/$(BIN)

# Actual target of the binary - depends on all .o files.
$(BUILD_DIR)/$(BIN) : $(OBJ)
	# Create build directories - same structure as sources.
	mkdir -p $(@D)
	# Just link all the object files.
	ar rcs $@ $^

# Build target for every single object file.
$(BUILD_DIR)/%.o : %.asm
	mkdir -p $(@D)
	# The -MMD flags additionaly creates a .d file with
	# the same name as the .o file.
	nasm -f $(NASM_FORMAT) $(NASM_FLAGS) $< -o $@

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
	#-rm $(BUILD_DIR)/$(BIN) $(OBJ) $(DEP)
	-rm -f -r $(BUILD_DIR)
