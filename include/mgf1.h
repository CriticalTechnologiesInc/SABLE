#ifndef __MGF1_H__
#define __MGF1_H__
/* Interface to generate a hash mask that may be used for encryption/decryption.
 */

extern const char *const xor_str;
extern const unsigned int xor_str_size;

BYTE *mgf1(BYTE *input, UINT32 inputLen, UINT32 outputLen);

#endif
