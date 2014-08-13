#
# Makefile for SABLE
#

LOADER=sable

CC=gcc
RM=rm -f
AS=as
AR=ar
LD=ld
OBJCOPY=objcopy

VERBOSE = @

C_SRCS := $(wildcard *.c)
S_SRCS := $(wildcard *.S)

OBJS := $(S_SRCS:.S=.o) $(C_SRCS:.c=.o)

checkcc    = $(shell if $(CC) $(1) -c -x c /dev/null -o /dev/null >/dev/null 2>&1; then echo "$(1)"; fi)
CCFLAGS   += -DEXEC -fno-builtin -fpack-struct -m32 -std=gnu99 -mregparm=3 -Iinclude/ -W -Wall -fstrict-aliasing -fomit-frame-pointer -minline-all-stringops -Winline  --param max-inline-insns-single=50
CCFLAGS	  += $(call checkcc,-fno-stack-protector)

ifeq ($(DEBUG),TRUE)
	CCFLAGS += -DDEBUG
endif

ifeq ($(SAVE_TPM),TRUE)
	CCFLAGS += -DSAVE_TPM
endif

sable: $(LOADER).ld $(OBJS)
	$(LD) -m elf_i386 -N -o $@ -T $^

.PHONY: clean
clean:
	$(VERBOSE) $(RM) $(LOADER) $(OBJS)

%.o: %.c
	$(VERBOSE) $(CC) $(CCFLAGS) -c $<
%.o: %.S
	$(VERBOSE) $(CC) $(CCFLAGS) -c $<
