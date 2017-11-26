#ifndef __KEYBOARD_H__
#define __KEYBOARD_H__

/* return a single char */
char getchar(void);
/* reads a null-terminated string from the terminal, up to strSize
 * in length, into str. If show is false, then the user input
 * is not displayed on the terminal. Returns the number of characters
 * read (not including the null terminating character). */
int get_string(char *str, unsigned int strSize, bool show);

/* 
 * debug Helper function 
 */ 

#endif

#define WAIT_FOR_INPUT() {                                      \
	char config_str[2];                                     \
	out_string("Enter to Continue ...");                    \
	get_string(config_str, sizeof(config_str) - 1, true);   \
}
