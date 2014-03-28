#include "util.h"
#include "hmac.h"

void do_xor(unsigned char * in1, unsigned char * in2, unsigned char* out,unsigned char size){
   for(int i=0;i<size;i++)
      out[i]=in1[i]^in2[i];
}

void pad(unsigned char * in, unsigned char val, unsigned char insize, unsigned char outsize){

   memset(in+insize,val,outsize-insize);

}

void hmac(
        struct Context *ctx, 
        BYTE *key, 
        BYTE keysize, 
        BYTE *text, 
        BYTE textsize)
{
   BYTE buf[1024];
   BYTE ipad[64];
   BYTE opad[64];
   memcpy(buf,key,keysize);

   //pad the key with 0s
   pad(buf,0,keysize,64);

   //generate ipad and opad
   pad(ipad,0x36,0,64);
   pad(opad,0x5c,0,64);

   //xor ipad with the key
   do_xor(buf,ipad,buf,64);

   memcpy(buf+64, text, textsize);

   sha1_init(ctx);   
   sha1(ctx,buf,64+textsize);
   sha1_finish(ctx);

   memcpy(buf,key,keysize);
   
   pad(buf,0,keysize,64);

   do_xor(buf,opad,buf,64);

   memcpy(buf+64, ctx->hash,20);   
 
   sha1_init(ctx);
   sha1(ctx,buf,64+20);
   sha1_finish(ctx);

}
