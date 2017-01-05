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

#include "dev.h"
#include "alloc.h"
#include "string.h"
#include "util.h"

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
 * Find a capability for a device in the capability list.
 * @param addr - address of the device in the pci config space
 * @param id   - the capability id to search.
 * @return 0 on failiure or the offset into the pci device of the capability
 */
static unsigned char pci_dev_find_cap(unsigned addr, unsigned char id) {
  CHECK3(-11, !(pci_read_long(addr + PCI_CONF_HDR_CMD) & 0x100000),
         s_no_capability_list_support);
  unsigned char cap_offset = pci_read_byte(addr + PCI_CONF_HDR_CAP);
  while (cap_offset)
    if (id == pci_read_byte(addr + cap_offset))
      return cap_offset;
    else
      cap_offset = pci_read_byte(addr + cap_offset + PCI_CAP_OFFSET);
  return 0;
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
  unsigned *bars = alloc(heap, 6, 0);
  unsigned *masks = alloc(heap, 6, 0);

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
      myprintf(s_pci_debug_format_string, ch, high_base, base, high_size, size);
  }

  // cleanup
  dealloc(heap, bars, 6);
  dealloc(heap, masks, 6);
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

static unsigned dev_get_addr(void) {
  unsigned addr;
  addr = pci_find_device(DEV_PCI_DEVICE_ID_OLD);
  if (!addr)
    addr = pci_find_device(DEV_PCI_DEVICE_ID_K10);
  if (!addr)
    addr = pci_find_device(DEV_PCI_DEVICE_ID_BLD);
  CHECK3(-21, !addr, s_device_not_found);
  addr = addr + pci_dev_find_cap(addr, DEV_PCI_CAP_ID);
  CHECK3(-22, !addr, s_cap_not_found);
  CHECK3(-23, 0xf != (pci_read_long(addr) & 0xf00ff), s_invalid_DEV_HDR);
  return addr;
}

/**
 * Disable all dev protection.
 */
int disable_dev_protection(void) {
  unsigned addr;
  out_info(s_disable_DEV_and_SLDEV_protection);
  addr = dev_get_addr();
  CHECK3(-30, !addr, s_DEV_not_found);
  dev_write_reg(addr, DEV_REG_CR, 0,
                dev_read_reg(addr, DEV_REG_CR, 0) &
                    ~(DEV_CR_SLDEV | DEV_CR_EN | DEV_CR_INVD));
  return 0;
}

static int enable_dev_bitmap(unsigned addr, unsigned base) {
  out_description(s_enable_dev_at, base);
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

/**
 * Enable dev protection for all memory.
 *
 * @param sldev_buffer - SLDEV protected buffer of 4k size (above 128k).
 * @param buffer - 128k buffer to hold the DEV bitmap of 128k size and 4k
 * alignment.
 */
int enable_dev_protection(unsigned *sldev_buffer, unsigned char *buffer) {
  unsigned addr;
  out_info(s_enable_DEV_protection);
  CHECK3(-41, (unsigned)buffer & 0xfff, s_dev_pointer_invalid);
  CHECK3(-42,
         (unsigned)sldev_buffer < 1 << 17 || (unsigned)sldev_buffer & 0xfff,
         s_sldev_pointer_invalid);
  addr = dev_get_addr();
  CHECK3(-43, !addr, s_DEV_not_found);

  /**
   * The DEV interface has a nasty race condition between memsetting
   * the DEV bitmap and flushing the cache. We avoid this by doing the
   * initialization twice. First using a SLDEV protected value to
   * protect the DEV bitmap and afterwards to switch to the real ones.
   */
  memset(sldev_buffer, 0xff, 1 << 12);
  unsigned base = (unsigned)sldev_buffer - ((unsigned)buffer >> 15);
  enable_dev_bitmap(addr, (base + 0xfff) & 0xfffff000);

  /**
   * Now we have the dev bitmap protected - initialize and enable them.
   */
  memset(buffer, 0xff, 1 << 17);
  enable_dev_bitmap(addr, base);
  return 0;
}