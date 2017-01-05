#ifndef KEYBOARD_H
#define KEYBOARD_H

#include "util.h"

#define STRING_BUF_SIZE 128
extern char string_buf[STRING_BUF_SIZE];

char getchar(void);
int get_string(unsigned int max_bytes, bool show);

#endif
