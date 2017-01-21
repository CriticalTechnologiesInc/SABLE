#ifndef KEYBOARD_H
#define KEYBOARD_H

#include "util.h"

/* return a single char */
char getchar(void);
/* reads a null-terminated string from the terminal, up to strSize
 * in length, into str. If show is false, then the user input
 * is not displayed on the terminal. Returns the number of characters
 * read (not including the null terminating character). */
int get_string(char *str, unsigned int strSize, bool show);

#endif
