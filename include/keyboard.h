#ifndef KEYBOARD_H
#define KEYBOARD_H

#include "util.h"

#define STRING_BUF_SIZE 128
extern char string_buf[STRING_BUF_SIZE];

/* return a single char */
char getchar(void);
/* reads a null-terminated string from the terminal, up to max_bytes
 * in length, into string_buf. If show is false, then the user input
 * is not displayed on the terminal. Returns the number of characters
 * read (not including the null terminating character). */
int get_string(unsigned int max_bytes, bool show);

#endif
