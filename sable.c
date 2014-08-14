/*
 * \brief   OSLO - Open Secure Loader
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


#include "version.h"
#include "util.h"
#include "sha.h"
#include "elf.h"
#include "sable_tpm.h"
#include "mp.h"
#include "dev.h"
#include "sable.h"
#include "alloc.h"

static const char *version_string = "SABLE " VERSION "\n";
const char * message_label = "SABLE:   ";
const unsigned REALMODE_CODE = 0x20000;
const char *CPU_NAME =  "AMD CPU booted by SABLE";

extern unsigned char g_slb_zero;
unsigned char g_end_of_low __attribute__((section (".slb.end_of_low"), aligned(4)));
unsigned char g_aligned_end_of_low __attribute__((section (".slb.aligned_end_of_low"), aligned(4096)));
unsigned char g_start_of_high __attribute__((section (".slb.start_of_high"), aligned(4)));
unsigned char g_end_of_high __attribute__((section (".slb.end_of_high"), aligned(4)));

/**
 * Function to output a hash.
 */
static void
show_hash(char *s, unsigned char *hash)
{
  out_string(message_label);
  out_string(s);
  for (unsigned i=0; i<20; i++)
    out_hex(hash[i], 7);
  out_char('\n');
}

void configure(unsigned char * passPhrase, unsigned long lenPassphrase)
{
	unsigned char buffer[1000];
    int res; 
    SessionCtx sctx;
    unsigned char usageAuthSRK[20];
    //select PCR 17 and 19
    sdTPM_PCR_SELECTION select = { ntohs(PCR_SELECT_SIZE), { 0x0, 0x0, 0xa } };
    unsigned char sealedData[400];
    memset((unsigned char *)&sctx,0,sizeof(SessionCtx));
    memset(usageAuthSRK,0,20);

    
    res = TPM_Start_OSAP(buffer,usageAuthSRK,TPM_ET_KEYHANDLE,TPM_KH_SRK,&sctx);
#ifdef DEBUG
    out_string("\nOSAP return value: ");
    out_hex(res,31);
    out_string("\n");
#endif

    res=TPM_Seal(buffer, select, passPhrase, lenPassphrase, sealedData, &sctx);
#ifdef DEBUG
    out_string("Seal (long) return value: ");
    out_hex(res,31);
    out_string("\n");
#endif
    ERROR(111,res!=0,"Seal (long) failed");

    out_string("\nErasing passphrase from memory...\n");
    memset(passPhrase,0,lenPassphrase);

    res = TPM_Start_OSAP(buffer,usageAuthSRK,TPM_ET_OWNER,0,&sctx);
#ifdef DEBUG
    out_string("\nOSAP return value: ");
    out_hex(res,31);
    out_string("\n");
#endif

#ifndef SAVE_TPM
    res = TPM_NV_DefineSpace(buffer, select, &sctx);
#ifdef DEBUG
    out_string("TPM_NV_DefineSpace return value: ");
    out_hex(res,31);
    out_string("\n");
    wait(5000);
#endif
#endif


    res=TPM_Start_OIAP(buffer,&sctx);
#ifdef DEBUG
    out_string("\nOIAP return value: ");
    out_hex(res,31);
#endif

#ifndef SAVE_TPM
    res = TPM_NV_WriteValueAuth(buffer,sealedData, 400,&sctx);
#ifdef DEBUG
    out_string("TPM_NV_WriteValueAuth return value: ");
    out_hex(res,31);
    out_string("\n");
    wait(5000);
#endif
#endif

}

void unsealPassphrase()
{
    unsigned char buffer[1000];
    int res; 
    SessionCtx sctx;
    SessionCtx sctxParent;
    SessionCtx sctxEntity;
    unsigned char usageAuthSRK[20];
    unsigned char sealedData[400];
    unsigned char unsealedData[100];
    UINT32 unsealedDataSize;
    memset((unsigned char *)&sctx,0,sizeof(SessionCtx));
    memset(usageAuthSRK,0,20);

    res=TPM_Start_OIAP(buffer,&sctx);
#ifdef DEBUG
    out_string("\nOIAP return value: ");
    out_hex(res,31);
#endif

    res = TPM_NV_ReadValueAuth(buffer, sealedData, 400, &sctx);
#ifdef DEBUG
    out_string("TPM_NV_ReadValueAuth return value: ");
    out_hex(res,31);
    out_string("\n");
#endif

    res=TPM_Start_OIAP(buffer,&sctxParent);
#ifdef DEBUG
    out_string("\nOIAP Parent return value: ");
    out_hex(res,31);
#endif

    res=TPM_Start_OIAP(buffer,&sctxEntity);
#ifdef DEBUG
    out_string("\nOIAP Entity return value: ");
    out_hex(res,31);
#endif

#ifndef SAVE_TPM
    res=TPM_Unseal(buffer,sealedData,unsealedData,100,&unsealedDataSize,&sctxParent,&sctxEntity);
#ifdef DEBUG
    out_string("\nUnseal return value: ");
    out_hex(res,31);
#endif
    if (res != 0)
        out_string("\nUnseal failed");
#endif

    out_string("\nPlease confirm that the passphrase shown below matches the one which was entered during system configuration. If the passphrase does not match, contact your systems administrator immediately.\n\n");
    out_string("Passphrase: ");
    out_string((char *)unsealedData);
    out_string("\n\nIf this is correct, type 'yes' in all capitals: ");
    char entry[20];
    char *correctEntry = "YES";
    unsigned int t = 0;
    char c;
    c = key_stroke_listener(); // for some reason, there's always an 'enter' char
    while(t < 20)
    {
      c = key_stroke_listener();
      if (c == 0x0D) break; // user hit 'return'
      if (c != 0) 
      {
          out_char(c);
          entry[t++] = c;
      }
    }
    out_string("\n");

    if (bufcmp(correctEntry, entry, 3))
        reboot();
}

/**
 *  Hash all multiboot modules.
 */
static
int
mbi_calc_hash(struct mbi *mbi, BYTE *config, BYTE* passPhrase, UINT32 passPhraseBufSize, UINT32 *lenPassPhrase, struct SHA1_Context *ctx, TPM_DIGEST *dig)
{
  unsigned res;

  CHECK3(-11, ~mbi->flags & MBI_FLAG_MODS, "module flag missing");
  CHECK3(-12, !mbi->mods_count, "no module to hash");
  out_description("Hashing modules count:", mbi->mods_count);

  struct module *m  = (struct module *) (mbi->mods_addr);
//check for if this has the magic value in the first module
//if it does, then skip the module, make mbi->mods_addr point to this new module
//set a flag that config file has been found
BYTE configmagic[20] = "SABLECONFIG";
if(!bufcmp(configmagic, (BYTE *)m->mod_start, strnlen_oslo(configmagic, 20))){
  out_info("config magic detected");
  *config = 1;

  out_string("Please enter the passphrase (64 char max): ");
  unsigned int t = 0;
  char c;
  c = key_stroke_listener(); // for some reason, there's always an 'enter' char
  while(t < passPhraseBufSize)
  {
      c = key_stroke_listener();
      if (c == 0x0D) break; // user hit 'return'
      if (c != 0) 
      {
          out_char(c);
          passPhrase[t++] = c;
      }
  }
  *lenPassPhrase = t + 1;
  out_string("\n");

	//clear module for security reasons
	memset((BYTE *)m->mod_start,0,m->mod_end-m->mod_start);

	//skip the module so it's invisible to future code
	m++;
	mbi->mods_addr = (unsigned) m;
	mbi->mods_count--;
	
}

  for (unsigned i=0; i < mbi->mods_count; i++, m++)
    {
      sha1_init(ctx);
      CHECK3(-13, m->mod_end < m->mod_start, "mod_end less than start");
      sha1(ctx, (BYTE *) m->mod_start, m->mod_end - m->mod_start);
      sha1_finish(ctx);
      memcpy(dig->digest, ctx->hash, sizeof(TPM_DIGEST));
      CHECK4(-14, (res = TPM_Extend(ctx->buffer, MODULE_PCR_ORD, dig)), "TPM extend failed", res);
    }
  return 0;
}


/**
 * Prepare the TPM for skinit.
 * Returns a TIS_INIT_* value.
 */
static
int
prepare_tpm(unsigned char *buffer)
{
  int tpm, res;

  CHECK4(-60, 0 >= (tpm = tis_init(TIS_BASE)), "tis init failed", tpm);
  CHECK3(-61, !tis_access(TIS_LOCALITY_0, 0), "could not gain TIS ownership");
  if ((res=TPM_Startup_Clear(buffer)) && res!=0x26)
    out_description("TPM_Startup() failed", res);

  CHECK3(-62, tis_deactivate_all(), "tis_deactivate failed");
  return tpm;
}


/**
 * This function runs before skinit and has to enable SVM in the processor
 * and disable all localities.
 */
int
__main(struct mbi *mbi, unsigned flags)
{

  unsigned char buffer[TCG_BUFFER_SIZE];

  // initialize the heap
  UINT32 heap_len = 0x00040000;
  init_allocator();
  add_mem_pool(heap, heap->head + sizeof(struct mem_node), heap_len);

  out_string(version_string);
  ERROR(10, !mbi || flags != MBI_MAGIC2, "not loaded via multiboot");

  // set bootloader name
  mbi->flags |= MBI_FLAG_BOOT_LOADER_NAME;
  mbi->boot_loader_name = (unsigned) version_string;

  int revision = 0;
  if (0 >= prepare_tpm(buffer) || (0 > (revision = check_cpuid())))
    {
      if (0 > revision)
	out_info("No SVM platform");
      else
	out_info("Could not prepare the TPM");

      ERROR(11, start_module(mbi), "start module failed");
    }

  out_description("SVM revision:", revision);
  ERROR(12, enable_svm(), "could not enable SVM");

  ERROR(13, stop_processors(), "sending an INIT IPI to other processors failed");

  out_info("call skinit");
  wait(1000);
  do_skinit();

  return 0;
}

/* Note: This function Assumes a 4KB stack.  A more elegant solution
 * would probably define some symbols and let the linker script
 * determine the stack size.
 */
void zero_stack (void) __attribute__ ((section (".text.slb")));
void zero_stack (void) 
{
    unsigned int esp;
    unsigned int stack_base;
    unsigned int ptr;

    __asm__ __volatile__("movl %%esp, %0 "
                         : "=m" (esp) );

    stack_base = (0xFFFFFFFF << 12) & esp;  // 2^12 = 4k

    if (stack_base <= 0) {
        // TODO: throw error!!!
      return;
    }

    // Zero out the stack 4 bytes at a time
    for (ptr = stack_base; ptr < esp; ptr+=4) {
      *((long*) ptr) = 0;
    }

    // Make sure we get the 0-3 bytes that may remain unzeroed
    for (ptr = ptr - 4; ptr < esp; ptr++) {
      *((char*) ptr) = 0;
    }
}

int
fixup(void)
{
  unsigned i;

  out_info("patch CPU name tag");
  CHECK3(-10, strlen(CPU_NAME)>=48,"cpu name to long");
  for (i=0; i<6; i++)
    wrmsr(0xc0010030+i, * (unsigned long long*) (CPU_NAME+i*8));

  out_info("halt APs in init state");
  int revision;

  /**
   * Start the stopped APs and execute some fixup code.
   */
  memcpy((char *) REALMODE_CODE, &smp_init_start, &smp_init_end - &smp_init_start);
  CHECK3(-2, start_processors(REALMODE_CODE), "sending an STARTUP IPI to other processors failed");


  CHECK3(12, (revision = enable_svm()), "could not enable SVM");
  out_description("SVM revision:", revision);

  out_info("enable global interrupt flag");
  asm volatile("stgi");
  return 0;
}

int revert_skinit(void)
{
  if (0 < check_cpuid())
    {
      if (disable_dev_protection())
        out_info("DEV disable failed");

      CHECK3(11, fixup(), "fixup failed");
      out_info("fixup done");
    }

  ERROR(12, pci_iterate_devices(), "could not iterate over the devices");

  return 0;
}

/* a useful test function */
void hello(void)
{
    out_info("hello, world!");
    wait(5000);
}

/**
 * This code is executed after skinit.
 */
/* int oslo(struct mbi *mbi) __attribute__ ((section (".text.slb"))); */
int oslo(struct mbi *mbi)
{
  struct SHA1_Context ctx;
  TPM_DIGEST dig;

  revert_skinit();

  int res;
  BYTE config=0;
  BYTE passPhrase[64];
  memset(passPhrase, 0, 64);
  UINT32 lenPassphrase = 0;

  ERROR(20, !mbi, "no mbi in oslo()");

  if (tis_init(TIS_BASE))
    {
    ERROR(21, !tis_access(TIS_LOCALITY_2, 0), "could not gain TIS ownership");
    CHECK4(24,(res = TPM_PcrRead(ctx.buffer, &dig, SLB_PCR_ORD)), "TPM_PcrRead failed", res);
#ifdef DEBUG
    show_hash("PCR[17]: ",dig.digest);
    wait(1000);
#endif
    ERROR(22, mbi_calc_hash(mbi,&config,passPhrase,64,&lenPassphrase, &ctx,&dig),  "calc hash failed");
#ifdef DEBUG
    show_hash("PCR[19]: ",dig.digest);
    dump_pcrs(ctx.buffer);
#endif

    if(config==1) {
      out_string("\nSealing passphrase: \n\n");
	  out_string((char *)passPhrase);
	  out_string("\n\nto PCR[a] with value \n");
      show_hash("PCR[19]: ",dig.digest);
	  wait(1000);

      configure(passPhrase,lenPassphrase);
      ERROR(25, tis_deactivate_all(), "tis_deactivate failed");
	  out_string("\nConfiguration complete. Rebooting now...\n");
	  wait(5000);
	  reboot();
    }
    else { 
      unsealPassphrase();
    }
        ERROR(25, tis_deactivate_all(), "tis_deactivate failed");

  }

  //zero_stack();

  ERROR(27, start_module(mbi), "start module failed");
  return 28;
}
