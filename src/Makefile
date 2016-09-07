# --- constants
CC=gcc
CFLAGS=-Wall -g -c
LFLAGS=-Wall -g 
BIN=../bin
DATA=../data
CLOAK_OBJECTS=cloak_main.o cloak_helpers.o common.o
UNCLOAK_OBJECTS=uncloak_main.o uncloak_helpers.o common.o

# --- targets
all:	$(BIN)/cloak $(BIN)/uncloak

$(BIN)/cloak:	$(CLOAK_OBJECTS)
	$(CC) $(LFLAGS) -o $(BIN)/cloak $(CLOAK_OBJECTS) -lgcrypt

$(BIN)/uncloak:	$(UNCLOAK_OBJECTS)
	$(CC) $(LFLAGS) -o $(BIN)/uncloak $(UNCLOAK_OBJECTS) -lgcrypt

# --- Store important suffixes in the .SUFFIXES macro
.SUFFIXES:	.o .c	

# --- Generate anyfile.o from anyfile.c
%.o: %.c defs.h Makefile
	$(CC) $(CFLAGS) $< 

$(DEFS_DEPENDENTS): defs.h
  
# --- remove relocatable objects and executable files
clean:
	rm -f $(BIN)/cloak $(BIN)/uncloak $(BIN)/run.log $(DATA)/bb.tiff $(DATA)/cc *.o

