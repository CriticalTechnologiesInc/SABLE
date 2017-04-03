/* Interface to generate a hash mask that may be used for encryption/decryption. */

BYTE * mgf1(BYTE *input, UINT32 inputLen, UINT32 outputLen);
