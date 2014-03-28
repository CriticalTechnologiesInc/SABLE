#include "sha.h"

void do_xor(unsigned char * in1, unsigned char * in2, unsigned char* out,unsigned char size);

void pad(unsigned char * in, unsigned char val, unsigned char insize, unsigned char outsize);

void hmac(struct Context *ctx, unsigned char *key, unsigned char keysize, unsigned char * text, unsigned char textsize);

