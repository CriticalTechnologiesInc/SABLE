#
# Makefile for the OSLO package.
#

ifeq ($(DEBUG),)
CCFLAGS += -Os -DNDEBUG
else
CCFLAGS += -Os -g
endif
VERBOSE = @


checkcc    = $(shell if $(CC) $(1) -c -x c /dev/null -o /dev/null >/dev/null 2>&1; then echo "$(1)"; fi)
CCFLAGS   += -m32 -std=gnu99 -mregparm=3 -Iinclude/ -W -Wall -ffunction-sections -fstrict-aliasing -fomit-frame-pointer -minline-all-stringops -Winline  --param max-inline-insns-single=50
CCFLAGS	  += $(call checkcc,-fno-stack-protector)
OBJ = asm.o util.o elf.o

.PHONY: all
all: zeroMem

zeroMem: zeroMem.ld $(OBJ) zeroMem.o
	$(LD) -m elf_i386 -gc-sections -N -o $@ -T $^

util.o:  include/asm.h include/util.h
elf.o:   include/asm.h include/util.h include/elf.h
zeroMem.o: include/asm.h include/util.h include/elf.h include/mbi.h

.PHONY: clean
clean:
	$(VERBOSE) rm -f zeroMem $(OBJ) zeroMem.o

%.o: %.c
	$(VERBOSE) $(CC) $(CCFLAGS) -c $<
%.o: %.S
	$(VERBOSE) $(CC) $(CCFLAGS) -c $<
