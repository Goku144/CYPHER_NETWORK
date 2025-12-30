PRG := cypher
CORE := core
LIB := lib
TARGET := $(CORE)/bin/$(PRG)

BINDIR ?= /usr/bin
INCDIR ?= /usr/include
COREDIR := $(CORE)/bin $(CORE)/lib $(CORE)/src
HDR := $(wildcard inc/*.h)
SRC := $(wildcard src/*.c lib/*.c)
# SRCOBJ := $(wildcard lib/*.c)
OBJ := $(addprefix $(CORE)/, $(SRC:.c=.o))
# SOBJ := $(addprefix $(CORE)/, $(SRCOBJ:.c=.so))

CC := gcc
CFLAG := -O3 -Wall
CINC := -I inc
CLIB := -lgmp
# CSF := -fPIC -shared

all: install

install: header $(TARGET) $(BINDIR)
	sudo install -m 775 $(TARGET) $(BINDIR)

header:
	sudo install -m 775 inc/cypher.h $(INCDIR)

$(BINDIR):
	install -d $(BINDIR)

$(TARGET): $(OBJ) $(SOBJ)
	$(CC) $(CFLAG) $^ $(CLIB) -o $@

$(CORE)/%.o: %.c $(COREDIR)
	$(CC) $(CFLAG) $(CINC) -c $< -o $@

# $(CORE)/%.so: %.c $(COREDIR)
# 	$(CC) $(CFLAG) $(CSF) $(CINC) $< -o $@

$(COREDIR):
	install -d $@

uninstall:
	sudo rm -f $(BINDIR)/$(PRG)
	sudo rm -f $(INCDIR)/cypher.h

clean:
	rm -rf $(TARGET) $(OBJ) $(SOBJ)