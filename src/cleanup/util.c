/*
 * \brief   Utility functions for a bootloader
 * \date    2006-03-28
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


#include "util.h"

/**
 * Wait roughly a given number of milliseconds.
 *
 * We use the PIT for this.
 */
void
wait(int ms)
{
  /* the PIT counts with 1.193 Mhz */
  ms*=1193;

  /* initalize the PIT, let counter0 count from 256 backwards */
  outb(0x43, 0x34);
  outb(0x40, 0);
  outb(0x40, 0);

  unsigned short state;
  unsigned short old = 0;
  while (ms>0)
    {
      outb(0x43, 0);
      state = inb(0x40);
      state |= inb(0x40) << 8;
      ms -= (unsigned short)(old - state);
      old = state;
    }
}

/**
 * Print the exit status and reboot the machine.
 */
void
__exit(unsigned status)
{
  out_char('\n');
  for (unsigned i=0; i<16;i++)
    {
      wait(1000);
      out_char('.');
    }
  out_string("-> OK, reboot now!\n");
  reboot();
}

/**
 * Output a single char.
 * Note: We allow only to put a char on the last line.
 */
int
out_char(unsigned value)
{
#define BASE(ROW) ((unsigned short *) (0xb8000+ROW*160))
  static unsigned int col;
  if (value!='\n')
    {
      unsigned short *p = BASE(24)+col;
      *p = 0x0f00 | value;
      col++;
    }

  if (col>=80 || value == '\n')
    {
      col=0;
      unsigned short *p=BASE(0);
      memcpy(p, p+80, 24*160);
      memset(BASE(24), 0, 160);
    }

  return value;
}

/**
 * Output a string.
 */
void
out_string(const char *value)
{
  for(; *value; value++)
    out_char(*value);
}

