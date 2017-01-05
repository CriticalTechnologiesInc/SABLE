#
# Makefile for SABLE
#

.PHONY: clean debug release

LOADER=sable

C_SRCS := $(wildcard *.c)
S_SRCS := $(wildcard *.S)

OBJS := $(S_SRCS:.S=.o) $(C_SRCS:.c=.o)

checkcc    = $(shell if $(CC) $(1) -c -x c /dev/null -o /dev/null >/dev/null 2>&1; then echo "$(1)"; fi)
CCFLAGS   += -Wall -Wno-main -DEXEC -fno-builtin -fpack-struct -m32 -std=gnu99 -mregparm=3 -Iinclude/ -fomit-frame-pointer -minline-all-stringops --param max-inline-insns-single=50 -Os -fstrict-aliasing -Wstrict-aliasing=0
CCFLAGS	  += $(call checkcc,-fno-stack-protector)
LDFLAGS   += -gc-sections -m elf_i386 -N

release: CCFLAGS += -DNDEBUG
release: sable

debug: CCFLAGS += -g
debug: sable

sable: $(LOADER).ld $(OBJS)
	$(LD) $(LDFLAGS) -o $@ -T $^

clean:
	$(VERBOSE) $(RM) $(LOADER) $(OBJS)

%.o: %.c
	$(CC) $(CCFLAGS) -c $<
%.o: %.S
	$(CC) $(CCFLAGS) -c $<
