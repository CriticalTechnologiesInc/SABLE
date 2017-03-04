/*
 * \brief   DEV and PCI code.
 * \date    2006-10-25
 * \author  Bernhard Kauer <kauer@tudos.org>
 */
/*
 * Copyright (C) 2006,2007,2010  Bernhard Kauer <kauer@tudos.org>
 * Technische Universitaet Dresden, Operating Systems Research Group
 *
 * This file is part of the OSLO package, which is distributed under
 * the  terms  of the  GNU General Public Licence 2.  Please see the
 * COPYING file for details.
 */

#ifndef ISABELLE
#include "asm.h"
#include "platform.h"
#include "alloc.h"
#include "exception.h"
#include "tcg.h"
#include "util.h"
#include "dev.h"
#include "mp.h"

// Generate RESULT types
RESULT_GEN(BYTE);

#define CPU_NAME "AMD CPU booted by SABLE"
const char *const cpu_name = CPU_NAME;

/**
 * Read a byte from the pci config space.
 */
unsigned char pci_read_byte(unsigned addr) {
  outl(PCI_ADDR_PORT, addr);
  return inb(PCI_DATA_PORT + (addr & 3));
}

/**
 * Read a word from the pci config space.
 */
unsigned short pci_read_word(unsigned addr) {
  outl(PCI_ADDR_PORT, addr);
  return inw(PCI_DATA_PORT + (addr & 2));
}

/**
 * Read a long from the pci config space.
 */
unsigned pci_read_long(unsigned addr) {
  outl(PCI_ADDR_PORT, addr);
  return inl(PCI_DATA_PORT);
}

/**
 * Write a word to the pci config space.
 */
void pci_write_word(unsigned addr, unsigned short value) {
  outl(PCI_ADDR_PORT, addr);
  outw(PCI_DATA_PORT + (addr & 2), value);
}

/**
 * Write a long to the pci config space.
 */
void pci_write_long(unsigned addr, unsigned value) {
  outl(PCI_ADDR_PORT, addr);
  outl(PCI_DATA_PORT, value);
}

/**
 * Read a word from the pci config space.
 */
static inline unsigned short pci_read_word_aligned(unsigned addr) {
  outl(PCI_ADDR_PORT, addr);
  return inw(PCI_DATA_PORT);
}

static inline void pci_write_word_aligned(unsigned addr, unsigned short value) {
  outl(PCI_ADDR_PORT, addr);
  outw(PCI_DATA_PORT, value);
}

/**
 * Return an pci config space address of a device with the given
 * class/subclass id or 0 on error.
 *
 * Note: this returns the last device found!
 */
unsigned pci_find_device_per_class(unsigned short class) {
  unsigned res = 0;
  for (unsigned i = 0; i < 1 << 13; i++) {
    unsigned char maxfunc = 0;
    for (unsigned func = 0; func <= maxfunc; func++) {
      unsigned addr = 0x80000000 | i << 11 | func << 8;
      if (!maxfunc && pci_read_byte(addr + 14) & 0x80)
        maxfunc = 7;
      if (class == (pci_read_long(addr + 0x8) >> 16))
        res = addr;
    }
  }
  return res;
}

/**
 * Return an pci config space address of a device with the given
 * device/vendor id or 0 on error.
 */
static unsigned pci_find_device(unsigned id) {
  unsigned res = 0;

  for (unsigned bus = 0; bus < 255; bus++)
    for (unsigned dev = 0; dev < 32; dev++) {
      unsigned char maxfunc = 0;
      for (unsigned func = 0; func <= maxfunc; func++) {
        unsigned addr = 0x80000000 | bus << 16 | dev << 11 | func << 8;
        unsigned value = pci_read_long(addr);

        unsigned char header_type = pci_read_byte(addr + 14);
        if (id == value)
          res = addr;
        if (!maxfunc && header_type & 0x80)
          maxfunc = 7;
        if (!value || value == 0xffffffff)
          continue;
      }
    }
  return res;
}

/**
 * EXCEPT: ERROR_PCI
 *
 * Find a capability for a device in the capability list.
 * @param addr - address of the device in the pci config space
 * @param id   - the capability id to search.
 * @return 0 on failiure or the offset into the pci device of the capability
 */
static RESULT_(BYTE) pci_dev_find_cap(unsigned addr, unsigned char id) {
  RESULT_(BYTE) ret = { .exception.error = NONE };
  ERROR(!(pci_read_long(addr + PCI_CONF_HDR_CMD) & 0x100000), ERROR_PCI,
         "no capability list support");
  ret.value = pci_read_byte(addr + PCI_CONF_HDR_CAP);
  while (ret.value)
    if (id == pci_read_byte(addr + ret.value))
      return ret;
    else
      ret.value = pci_read_byte(addr + ret.value + PCI_CAP_OFFSET);
  return ret;
}

void myprintf(const char *fmt, char ch, unsigned high_base, unsigned base,
              unsigned high_size, unsigned size) {
  UNUSED(fmt); // to suppress a warning

  out_char(ch);
  out_hex(high_base, 31);
  out_char('_');
  out_hex(base, 31);
  out_char(' ');
  out_hex(high_size, 31);
  out_char('_');
  out_hex(size, 31);
  out_char('\n');
}

/**
 * Print pci bars.
 */
void pci_print_bars(unsigned addr, unsigned count) {
  unsigned bars[6];
  unsigned masks[6];

  // disable device
  short cmd = pci_read_word_aligned(addr + 0x4);
  pci_write_word_aligned(addr + 0x4, 0);

  // read bars and masks
  for (unsigned i = 0; i < count; i++) {
    unsigned a = addr + 0x10 + i * 4;
    bars[i] = pci_read_long(a);
    pci_write_long(a, ~0);
    masks[i] = ~pci_read_long(a);
    pci_write_long(a, bars[i]);
  }
  // reenable device
  pci_write_word_aligned(addr + 0x4, cmd);

  for (unsigned i = 0; i < count; i++) {
    unsigned base, high_base = 0;
    unsigned size, high_size = 0;
    char ch;
    if (bars[i] & 0x1) {
      base = bars[i] & 0xfffe;
      size = (masks[i] & 0xfffe) | 1 | base;
      ch = 'i';
    } else {
      ch = 'm';
      base = bars[i] & ~0xf;
      size = masks[i] | 0xf | base;
      if ((bars[i] & 0x6) == 4 && i < 5) {
        high_base = bars[i + 1];
        high_size = masks[i + 1] | high_base;
        i++;
      }
    }
    if (base)
      myprintf("    %c: %#x%x/%#x%x", ch, high_base, base, high_size, size);
  }
}

/**
 * Iterate over all devices in the pci config space.
 */
int pci_iterate_devices(void) {
  for (unsigned bus = 0; bus < 255; bus++)
    for (unsigned dev = 0; dev < 32; dev++) {
      unsigned char maxfunc = 0;
      for (unsigned func = 0; func <= maxfunc; func++) {
        unsigned addr = 0x80000000 | bus << 16 | dev << 11 | func << 8;
        unsigned value = pci_read_long(addr);
#ifndef NDEBUG
        unsigned class = pci_read_long(addr + 0x8) >> 16;
#endif

        unsigned char header_type = pci_read_byte(addr + 14);
        if (!maxfunc && header_type & 0x80)
          maxfunc = 7;
        if (!value || value == 0xffffffff)
          continue;
#ifndef NDEBUG
        out_hex(bus, 7);
        out_char(':');
        out_hex(dev, 4);
        out_char('.');
        out_hex(func, 3);
        out_char(' ');
        out_hex(class, 15);
        out_char(':');
        out_char(' ');
        out_hex(value & 0xffff, 15);
        out_char(':');
        out_hex(value >> 16, 15);
        out_char(' ');
        out_hex(header_type, 7);
        out_char('\n');
#endif
      }
    }
  return 0;
}

/**
 * Read a DEV control or status register.
 * @param addr - pci config address of the capability header
 */
static unsigned dev_read_reg(unsigned addr, unsigned char func,
                             unsigned char instance) {
  pci_write_long(addr + DEV_OFFSET_OP, (func << 8) | instance);
  return pci_read_long(addr + DEV_OFFSET_DATA);
}

/**
 * Write a DEV control or status register.
 * @param addr - the pci config address of the capability header
 */
static void dev_write_reg(unsigned addr, unsigned char func,
                          unsigned char instance, unsigned value) {
  pci_write_long(addr + DEV_OFFSET_OP, (func << 8) | instance);
  pci_write_long(addr + DEV_OFFSET_DATA, value);
}

/* EXCEPT:
 * ERROR_PCI
 * ERROR_DEV
 */
static RESULT_(UINT32) dev_get_addr(void) {
  RESULT_(UINT32) ret = { .exception.error = NONE };
  ret.value = pci_find_device(DEV_PCI_DEVICE_ID_OLD);
  if (!ret.value)
    ret.value = pci_find_device(DEV_PCI_DEVICE_ID_K10);
  if (!ret.value)
    ret.value = pci_find_device(DEV_PCI_DEVICE_ID_BLD);
  ERROR(!ret.value, ERROR_DEV, "DEV not found");
  RESULT_(BYTE) cap_ret = pci_dev_find_cap(ret.value, DEV_PCI_CAP_ID);
  THROW(cap_ret.exception);
  ret.value = ret.value + cap_ret.value;
  ERROR(!ret.value, ERROR_DEV, "cap not found");
  ERROR(0xf != (pci_read_long(ret.value) & 0xf00ff), ERROR_DEV, "invalid DEV_HDR");
  return ret;
}

/* EXCEPT:
 * ERROR_PCI
 * ERROR_DEV
 *
 * Disable all dev protection.
 */
RESULT disable_dev_protection(void) {
  RESULT ret = { .exception.error = NONE };
  RESULT_(UINT32) addr_ret;
  out_info("disable DEV and SLDEV protection");
  addr_ret = dev_get_addr();
  THROW(addr_ret.exception);
  dev_write_reg(addr_ret.value, DEV_REG_CR, 0,
                dev_read_reg(addr_ret.value, DEV_REG_CR, 0) &
                    ~(DEV_CR_SLDEV | DEV_CR_EN | DEV_CR_INVD));
  return ret;
}

static int enable_dev_bitmap(unsigned addr, unsigned base) {
  out_description("enable dev at", base);
  unsigned dom = (dev_read_reg(addr, DEV_REG_CAP, 0) >> 8) & 0xff;
  while (dom) {
    dev_write_reg(addr, DEV_REG_BASE_HI, dom, 0);
    dev_write_reg(addr, DEV_REG_BASE_HI, dom, base | 3);
    dom--;
  }
  dev_write_reg(addr, DEV_REG_CR, 0,
                dev_read_reg(addr, DEV_REG_CR, 0) | DEV_CR_EN | DEV_CR_INVD);
  return 0;
}

/* EXCEPT:
 * ERROR_DEV
 * ERROR_PCI
 *
 * Enable dev protection for all memory.
 *
 * @param sldev_buffer - SLDEV protected buffer of 4k size (above 128k).
 * @param buffer - 128k buffer to hold the DEV bitmap of 128k size and 4k
 * alignment.
 */
RESULT enable_dev_protection(unsigned *sldev_buffer, unsigned char *buffer) {
  RESULT ret = { .exception.error = NONE };
  RESULT_(UINT32) addr_ret;
  out_info("enable DEV protection");
  ERROR((unsigned)buffer & 0xfff, ERROR_DEV, "DEV pointer invalid");
  ERROR((unsigned)sldev_buffer < 1 << 17 || (unsigned)sldev_buffer & 0xfff,
         ERROR_DEV, "SL_DEV pointer invalid");
  addr_ret = dev_get_addr();
  THROW(addr_ret.exception);

  /**
   * The DEV interface has a nasty race condition between memsetting
   * the DEV bitmap and flushing the cache. We avoid this by doing the
   * initialization twice. First using a SLDEV protected value to
   * protect the DEV bitmap and afterwards to switch to the real ones.
   */
  memset(sldev_buffer, 0xff, 1 << 12);
  unsigned base = (unsigned)sldev_buffer - ((unsigned)buffer >> 15);
  enable_dev_bitmap(addr_ret.value, (base + 0xfff) & 0xfffff000);

  /**
   * Now we have the dev bitmap protected - initialize and enable them.
   */
  memset(buffer, 0xff, 1 << 17);
  enable_dev_bitmap(addr_ret.value, base);
  return ret;
}

#define REALMODE_CODE 0x20000
extern char smp_init_start;
extern char smp_init_end;

/* EXCEPT:
 * ERROR_APIC
 * ERROR_SVM_ENABLE
 */
static RESULT fixup(void) {
  RESULT ret = { .exception.error = NONE };
  unsigned i;
  out_info("patch CPU name tag");

  for (i = 0; i < 6; i++)
    wrmsr(0xc0010030 + i, *(unsigned long long *)(cpu_name + i * 8));

  out_info("halt APs in init state");
  /**
   * Start the stopped APs and execute some fixup code.
   */
  memcpy((char *)REALMODE_CODE, &smp_init_start,
         &smp_init_end - &smp_init_start);
  RESULT start_proc_ret = start_processors(REALMODE_CODE);
  THROW(start_proc_ret.exception);
  RESULT enable_svm_ret = enable_svm();
  THROW(enable_svm_ret.exception);

  out_info("Enable global interrupt flag");
  asm volatile("stgi");

  return ret;
}

/* EXCEPT:
 * ERROR_PCI
 * ERROR_DEV
 * ERROR_APIC
 * ERROR_SVM
 * ERROR_NO_EXT
 * ERROR_NO_APIC
 * ERROR_NO_SVM
 */
RESULT revert_skinit(void) {
  RESULT ret = { .exception.error = NONE };
  RESULT_(UINT32) cpuid = check_cpuid();
  THROW(cpuid.exception);

  RESULT dev_ret = disable_dev_protection();
  THROW(dev_ret.exception);

  RESULT fixup_ret = fixup();
  THROW(fixup_ret.exception);
  out_info("fixup done");

  return ret;
}
#endif
