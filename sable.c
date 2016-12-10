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


#include "include/alloc.h"
#include "include/tpm_error.h"
#include "include/version.h"
#include "include/util.h"
#include "include/sha.h"
#include "include/elf.h"
#include "include/sable_tpm.h"
#include "include/mp.h"
#include "include/dev.h"
#include "include/sable.h"

#ifdef EXEC
static const char *version_string = "SABLE " VERSION "\n";
const char * message_label = "SABLE:   ";
const unsigned REALMODE_CODE = 0x20000;
const char *CPU_NAME =  "AMD CPU booted by SABLE";
#else
static const char *version_string;
const char * message_label;
const unsigned REALMODE_CODE = 0x20000;
const char *CPU_NAME;
#endif

static char config = 0;

extern BYTE g_slb_zero;
#ifdef EXEC
BYTE g_end_of_low __attribute__((section (".slb.end_of_low"), aligned(4)));
BYTE g_aligned_end_of_low __attribute__((section (".slb.aligned_end_of_low"), aligned(4096)));
BYTE g_start_of_high __attribute__((section (".slb.start_of_high"), aligned(4)));
BYTE g_end_of_high __attribute__((section (".slb.end_of_high"), aligned(4)));
#endif

/**
 * Function to output a hash.
 */
static void
show_hash(char *s, TPM_DIGEST *hash)
{
  out_string(message_label);
  out_string(s);
  for (UINT32 i = 0; i < 20; i++)
    out_hex(hash->digest[i], 7);
  out_char('\n');
}

void configure(BYTE *passPhrase, UINT32 lenPassphrase, BYTE *ownerAuthData, BYTE *srkAuthData, BYTE *passPhraseAuthData)
{
    BYTE *buffer = alloc(heap, TCG_BUFFER_SIZE, 0);
    TPM_RESULT res; 
    SessionCtx *sctx = alloc(heap, sizeof(SessionCtx), 0);
    BYTE *sealedData = alloc(heap, 400, 0);

    memset((unsigned char *)sctx, 0, sizeof(SessionCtx));

    //select PCR 17 and 19
    sdTPM_PCR_SELECTION select = { ntohs(PCR_SELECT_SIZE), { 0x0, 0x0, 0xa } };
    
    res = TPM_Start_OSAP(buffer,srkAuthData,TPM_ET_KEYHANDLE,TPM_KH_SRK,sctx);
#ifdef EXEC
    TPM_ERROR(res, "TPM_Start_OSAP()");
#else
    TPM_ERROR(res, &string_literal);
#endif

#ifdef EXEC
    out_string("\nErasing srk authdata from memory...\n");
#else
    out_string(&string_literal);
#endif
    memset(srkAuthData, 0, 20);

    res = TPM_Seal(buffer, select, passPhrase, lenPassphrase, sealedData, sctx, passPhraseAuthData);
#ifdef EXEC
    TPM_ERROR(res, "TPM_Seal()");
#else
    TPM_ERROR(res, &string_literal);
#endif

#ifdef EXEC
    out_string("\nErasing passphrase from memory...\n");
#else
    out_string(&string_literal);
#endif
    memset(passPhrase, 0, lenPassphrase);
    
#ifdef EXEC
    out_string("\nErasing passphrase authdata from memory...\n");
#else
    out_string(&string_literal);
#endif
    memset(passPhraseAuthData, 0, 20);

    res = TPM_Start_OSAP(buffer,ownerAuthData,TPM_ET_OWNER,0,sctx);
#ifdef EXEC
    TPM_ERROR(res, "TPM_Start_OSAP()");
#else
    TPM_ERROR(res, &string_literal);
#endif

#ifdef EXEC
    out_string("\nErasing owner authdata from memory...\n");
#else
    out_string(&string_literal);
#endif
    memset(ownerAuthData, 0, 20);

#ifndef SAVE_TPM
    res = TPM_NV_DefineSpace(buffer, select, sctx);
#ifdef EXEC
    TPM_ERROR(res, "TPM_NV_DefineSpace()");
#else
    TPM_ERROR(res, &string_literal);
#endif
#endif

    res = TPM_Start_OIAP(buffer,sctx);
#ifdef EXEC
    TPM_ERROR(res, "TPM_Start_OIAP()");
#else
    TPM_ERROR(res, &string_literal);
#endif

#ifndef SAVE_TPM
    res = TPM_NV_WriteValueAuth(buffer,sealedData, 400,sctx);
#ifdef EXEC
    TPM_ERROR(res, "TPM_NV_WriteValueAuth()");
#else
    TPM_ERROR(res, &string_literal);
#endif
#endif

    // cleanup
    dealloc(heap, buffer, TCG_BUFFER_SIZE);
    dealloc(heap, sctx, sizeof(SessionCtx));
    dealloc(heap, sealedData, 400);
}

void 
unsealPassphrase(BYTE *srkAuthData, BYTE *passPhraseAuthData)
{
    TPM_RESULT res; 

    BYTE *buffer = alloc(heap, TCG_BUFFER_SIZE, 0);
    SessionCtx *sctx = alloc(heap, sizeof(SessionCtx), 0);
    SessionCtx *sctxParent = alloc(heap, sizeof(SessionCtx), 0);
    SessionCtx *sctxEntity = alloc(heap, sizeof(SessionCtx), 0);
    char *entry = alloc(heap, 20 * sizeof(char), 0);

    BYTE *sealedData = alloc(heap, 400, 0);
    BYTE *unsealedData = alloc(heap, 100, 0);

    UINT32 *unsealedDataSize = alloc(heap, sizeof(UINT32), 0);
    memset(sctx, 0, sizeof(SessionCtx));
    
    memcpy(sctxParent->pubAuth.authdata, srkAuthData, 20);
    memcpy(sctxEntity->pubAuth.authdata, passPhraseAuthData, 20);

    res = TPM_Start_OIAP(buffer, sctx);
#ifdef EXEC
    TPM_ERROR(res, "TPM_Start_OIAP()");
#else
    TPM_ERROR(res, &string_literal);
#endif

    res = TPM_NV_ReadValueAuth(buffer, sealedData, 400, sctx);
#ifdef EXEC
    TPM_ERROR(res, "TPM_NV_ReadValueAuth()");
#else
    TPM_ERROR(res, &string_literal);
#endif

    res = TPM_Start_OIAP(buffer, sctxParent);
#ifdef EXEC
    TPM_ERROR(res, "TPM_Start_OSAP()");
#else
    TPM_ERROR(res, &string_literal);
#endif

    res = TPM_Start_OIAP(buffer, sctxEntity);
#ifdef EXEC
    TPM_ERROR(res, "TPM_Start_OIAP()");
#else
    TPM_ERROR(res, &string_literal);
#endif

#ifndef SAVE_TPM
    res = TPM_Unseal(buffer, sealedData, unsealedData, 100, unsealedDataSize, sctxParent, sctxEntity);
#ifdef EXEC
    TPM_WARNING(res, "TPM_Unseal()");
#else
    TPM_WARNING(res, &string_literal);
#endif
#endif

#ifdef EXEC
    out_string("\nPlease confirm that the passphrase shown below matches the one which was entered during system configuration. If the passphrase does not match, contact your systems administrator immediately.\n\n");
#else
    out_string(&string_literal);
#endif

#ifdef EXEC
    out_string("Passphrase: ");
#else
    out_string(&string_literal);
#endif

    out_string((char *) unsealedData);

#ifdef EXEC
    out_string("\n\nIf this is correct, type 'yes' in all capitals: ");
#else
    out_string(&string_literal);
#endif

#ifdef EXEC
    char *correctEntry = "YES";
#else
    char *correctEntry = &string_literal;
#endif

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
          entry[t] = c;
          t++;
      }
    }
    out_char('\n');

    if (bufcmp(correctEntry, entry, 3))
        reboot();
    
#ifdef EXEC
    out_string("\nErasing passphrase authdata from memory...\n");
#else
    out_string(&string_literal);
#endif
    memset(passPhraseAuthData, 0, 20);

#ifdef EXEC
    out_string("\nErasing srk authdata from memory...\n");
#else
    out_string(&string_literal);
#endif
    memset(srkAuthData, 0, 20);

    // cleanup
    dealloc(heap, buffer, TCG_BUFFER_SIZE);
    dealloc(heap, sctx, sizeof(SessionCtx));
    dealloc(heap, sctxParent, sizeof(SessionCtx));
    dealloc(heap, sctxEntity, sizeof(SessionCtx));

    dealloc(heap, sealedData, 400);
    dealloc(heap, unsealedData, 100);
    dealloc(heap, unsealedDataSize, sizeof(UINT32));
}

/**
 *  Hash all multiboot modules.
 */
static
int
mbi_calc_hash(struct mbi *mbi, BYTE* passPhrase, UINT32 passPhraseBufSize, UINT32 *lenPassPhrase, struct SHA1_Context *ctx, TPM_DIGEST *dig)
{
    TPM_RESULT res;

#ifdef EXEC
    CHECK3(-11, ~mbi->flags & MBI_FLAG_MODS, "module flag missing");
    CHECK3(-12, !mbi->mods_count, "no module to hash");
    out_description("Hashing modules count:", mbi->mods_count);
#else
    CHECK3(-11, ~mbi->flags & MBI_FLAG_MODS, &string_literal);
    CHECK3(-12, !mbi->mods_count, &string_literal);
    out_description(&string_literal, mbi->mods_count);
#endif

    struct module *m  = (struct module *) (mbi->mods_addr);
    //
    //check for if this has the magic value in the first module
    //if it does, then skip the module, make mbi->mods_addr point to this new module
    //set a flag that config file has been found
    if(!bufcmp((BYTE *)configmagic, (BYTE *)m->mod_start, strnlen_sable((BYTE *)configmagic, 20))){
#ifdef DEBUG
        out_info("config magic detected");
#endif
        config = 1;

#ifdef EXEC
        out_string("Please enter the passphrase (64 char max): ");
#else
        out_string(&string_literal);
#endif

        UINT32 t = 0;
        char c = key_stroke_listener(); // for some reason, there's always an 'enter' char
        while(t < passPhraseBufSize)
        {
            c = key_stroke_listener();
            if (c == 0x0D) break; // user hit 'return'
            if (c != 0) 
            {
                out_char(c);
                passPhrase[t] = c;
                t++;
            }
        }
        *lenPassPhrase = t + 1;
        out_char('\n');

	    //clear module for security reasons
	    memset((BYTE *)m->mod_start, 0, m->mod_end-m->mod_start);

	    //skip the module so it's invisible to future code
	    m++;
	    mbi->mods_addr = (unsigned) m;
	    mbi->mods_count--;
    }

    for (unsigned i = 0; i < mbi->mods_count; i++, m++)
    {
        sha1_init(ctx);

#ifdef EXEC
        CHECK3(-13, m->mod_end < m->mod_start, "mod_end less than start");
#else
        CHECK3(-13, m->mod_end < m->mod_start, &string_literal);
#endif

#ifdef DEBUG
	out_description("Module starts at ", m->mod_start);
	out_description("Module ends at ", m->mod_end);
#endif

        sha1(ctx, (BYTE *) m->mod_start, m->mod_end - m->mod_start);
        sha1_finish(ctx);
        memcpy(dig->digest, ctx->hash, sizeof(TPM_DIGEST));
        res = TPM_Extend(ctx->buffer, MODULE_PCR_ORD, dig);
#ifdef EXEC
        TPM_ERROR(res, "TPM_Extend()");
#else
        TPM_ERROR(res, &string_literal);
#endif

    }

    wait(10000);

    return 0;
}


/**
 * Prepare the TPM for skinit.
 * Returns a TIS_INIT_* value.
 */
static
int
prepare_tpm(BYTE *buffer)
{
    int tpm;
    TPM_RESULT res;

    tpm = tis_init(TIS_BASE);

#ifdef EXEC
    CHECK4(-60, 0 >= tpm, "tis init failed", tpm);
#else
    CHECK4(-60, 0 >= tpm, &string_literal, tpm);
#endif

#ifdef EXEC
    CHECK3(-61, !tis_access(TIS_LOCALITY_0, 0), "could not gain TIS ownership");
#else
    CHECK3(-61, !tis_access(TIS_LOCALITY_0, 0), &string_literal);
#endif

    res = TPM_Startup_Clear(buffer);
    if (res && res != TPM_E_INVALID_POSTINIT)
#ifdef EXEC
        TPM_ERROR(res, "TPM_Startup_Clear()");
#else
        TPM_ERROR(res, &string_literal);
#endif

#ifdef EXEC
    CHECK3(-62, tis_deactivate_all(), "tis_deactivate failed");
#else
    CHECK3(-62, tis_deactivate_all(), &string_literal);
#endif

    return tpm;
}


/**
 * This function runs before skinit and has to enable SVM in the processor
 * and disable all localities.
 */
int
main(struct mbi *mbi, unsigned flags)
{

    // initialize the heap
    UINT32 heap_len = 0x00040000;
    init_allocator();
    add_mem_pool(heap, heap->head + sizeof(struct mem_node), heap_len);

    BYTE *buffer = alloc(heap, TCG_BUFFER_SIZE, 0);

    out_string(version_string);
#ifdef EXEC
    ERROR(10, !mbi || flags != MBI_MAGIC2, "not loaded via multiboot");
#else
    ERROR(10, !mbi || flags != MBI_MAGIC2, &string_literal);
#endif

    // set bootloader name
    mbi->flags |= MBI_FLAG_BOOT_LOADER_NAME;
    mbi->boot_loader_name = (unsigned) version_string;

    int revision = check_cpuid();
    if (0 >= prepare_tpm(buffer) || (0 > revision))
    {
        if (0 > revision)
#ifdef EXEC
	        out_info("No SVM platform");
#else
	        out_info(&string_literal);
#endif
        else
#ifdef EXEC
	        out_info("Could not prepare the TPM");
#else
	        out_info(&string_literal);
#endif

#ifdef EXEC
        ERROR(11, start_module(mbi), "start module failed");
#else
        ERROR(11, start_module(mbi), &string_literal);
#endif
    }

#ifdef EXEC
    out_description("SVM revision:", revision);
    ERROR(12, enable_svm(), "could not enable SVM");
    ERROR(13, stop_processors(), "sending an INIT IPI to other processors failed");
#else
    out_description(&string_literal, revision);
    ERROR(12, enable_svm(), &string_literal);
    ERROR(13, stop_processors(), &string_literal);
#endif

    // cleanup
    dealloc(heap, buffer, TCG_BUFFER_SIZE);

#ifdef DEBUG
    out_info("call skinit");
    wait(1000);
#endif
    do_skinit();

    return 0;
}

/* Note: This function Assumes a 4KB stack.  A more elegant solution
 * would probably define some symbols and let the linker script
 * determine the stack size.
 */
/*
void zero_stack (void) __attribute__ ((section (".text.slb")));
void zero_stack (void) 
{
    unsigned int esp;
    unsigned int stack_base;
    unsigned int ptr;

    __asm__ __volatile__("movl %%esp, %0 " : "=m" (esp) );

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
*/

int
fixup(void)
{
    unsigned i;

#ifdef EXEC
    out_info("patch CPU name tag");
#else
    out_info(&string_literal);
#endif

#ifdef EXEC
    CHECK3(-10, strnlen_sable((BYTE *)CPU_NAME, 1024)>=48,"cpu name to long");
#else
    CHECK3(-10, strnlen_sable((BYTE *)CPU_NAME, 1024)>=48,&string_literal);
#endif

    for (i = 0; i<6; i++)
        wrmsr(0xc0010030+i, * (unsigned long long*) (CPU_NAME+i*8));

#ifdef EXEC
    out_info("halt APs in init state");
#else
    out_info(&string_literal);
#endif
    int revision;

    /**
     * Start the stopped APs and execute some fixup code.
     */
    memcpy((char *) REALMODE_CODE, &smp_init_start, &smp_init_end - &smp_init_start);
#ifdef EXEC
    CHECK3(-2, start_processors(REALMODE_CODE), "sending an STARTUP IPI to other processors failed");
#else
    CHECK3(-2, start_processors(REALMODE_CODE), &string_literal);
#endif

    revision = enable_svm();
#ifdef EXEC
    CHECK3(12, revision, "could not enable SVM");
    out_description("SVM revision:", revision);
#else
    CHECK3(12, revision, &string_literal);
    out_description(&string_literal, revision);
#endif

#ifdef EXEC
    out_info("enable global interrupt flag");
#else
    out_info(&string_literal);
#endif

#ifdef EXEC
    asm volatile("stgi");  // Not included in proof!
#endif

    return 0;
}

int revert_skinit(void)
{
    if (0 < check_cpuid())
    {
        if (disable_dev_protection())
#ifdef EXEC
            out_info("DEV disable failed");
#else
            out_info(&string_literal);
#endif

#ifdef EXEC
        CHECK3(11, fixup(), "fixup failed");
#else
        CHECK3(11, fixup(), &string_literal);
#endif
#ifdef EXEC
        out_info("fixup done");
#else
        out_info(&string_literal);
#endif
    }

#ifdef EXEC
    ERROR(12, pci_iterate_devices(), "could not iterate over the devices");
#else
    ERROR(12, pci_iterate_devices(), &string_literal);
#endif

    return 0;
}

/**
 * This code is executed after skinit.
 */
/* int sable(struct mbi *mbi) __attribute__ ((section (".text.slb"))); */
int 
sable(struct mbi *mbi)
{
    TPM_RESULT res;
    struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);
    struct SHA1_Context *ctxSrk = alloc(heap, sizeof(struct SHA1_Context), 0);
    struct SHA1_Context *ctxOwn = alloc(heap, sizeof(struct SHA1_Context), 0);    
    struct SHA1_Context *ctxPas = alloc(heap, sizeof(struct SHA1_Context), 0);     
    TPM_DIGEST *dig = alloc(heap, sizeof(TPM_DIGEST), 0);
    BYTE *ownerAuthData = alloc(heap, 20, 0); 
    BYTE *srkAuthData = alloc(heap, 20, 0);
    BYTE *passPhraseAuthData = alloc(heap, 20, 0);
    BYTE *passPhrase = alloc(heap, 64, 0);
    UINT32 *lenPassphrase = alloc(heap, sizeof(UINT32), 0);
    UINT32 ownerAuthLen;
    UINT32 srkAuthLen;
    UINT32 passAuthLen;

    revert_skinit();

    memset(passPhrase, 0, 64);
    *lenPassphrase = 0;
    memset(ownerAuthData, 0, 20);
    ownerAuthLen = 0;
    memset(srkAuthData, 0, 20);
    srkAuthLen = 0;
    memset(passPhraseAuthData, 0, 20);
    passAuthLen = 0;

#ifdef EXEC
    ERROR(20, !mbi, "no mbi in sable()");
#else
    ERROR(20, !mbi, &string_literal);
#endif
    
#ifdef EXEC
    out_string("Please enter the srkAuthData (20 char max): ");
#else
    out_string(&string_literal);
#endif
    
    srkAuthLen = keyboardReader(srkAuthData,20);  

    if (srkAuthLen > 0) {
      sha1_init(ctxSrk);
      sha1(ctxSrk, srkAuthData, srkAuthLen);
      sha1_finish(ctxSrk);
    }
    else {
      memset(ctxSrk->hash,0,20);
    }

#ifdef EXEC
    out_string("Please enter the passPhraseAuthData (20 char max): ");
#else
    out_string(&string_literal);
#endif
    
    passAuthLen = keyboardReader(passPhraseAuthData, 20);

    if (passAuthLen > 0) {
      sha1_init(ctxPas);
      sha1(ctxPas, passPhraseAuthData, passAuthLen);
      sha1_finish(ctxPas);
    }
    else {
      memset(ctxPas->hash,0,20);
    }

    if (tis_init(TIS_BASE))
    {

#ifdef EXEC
        ERROR(21, !tis_access(TIS_LOCALITY_2, 0), "could not gain TIS ownership");
#else
        ERROR(21, !tis_access(TIS_LOCALITY_2, 0), &string_literal);
#endif

        res = TPM_PcrRead(ctx->buffer, dig, SLB_PCR_ORD);
#ifdef EXEC
        TPM_ERROR(res, "TPM_PcrRead()");
#else
        TPM_ERROR(res, &string_literal);
#endif

#ifdef DEBUG
        show_hash("PCR[17]: ", dig);
        wait(1000);
#endif

#ifdef EXEC
        ERROR(22, mbi_calc_hash(mbi,passPhrase,64,lenPassphrase, ctx, dig),  "calc hash failed");
#else
        ERROR(22, mbi_calc_hash(mbi,passPhrase,64,lenPassphrase, ctx, dig),  &string_literal);
#endif

#ifdef DEBUG
        show_hash("PCR[19]: ", dig);
        dump_pcrs(ctx->buffer);
#endif

        if (config == 1) {

#ifdef EXEC
            out_string("\nSealing passphrase: \n\n");
#else
            out_string(&string_literal);
#endif

	        out_string((char *)passPhrase);

#ifdef EXEC
	        out_string("\n\nto PCR[19] with value \n");
#else
	        out_string(&string_literal);
#endif

#ifdef EXEC
            show_hash("PCR[19]: ", dig);
#else
            show_hash(&string_literal, dig);
#endif

	        wait(1000);

            #ifdef EXEC
    out_string("Please enter the ownerAuthData (20 char max): ");
#else
    out_string(&string_literal);
#endif
    
    ownerAuthLen = keyboardReader(ownerAuthData,20);
    
    if (ownerAuthLen > 0) {
      sha1_init(ctxOwn);
      sha1(ctxOwn, ownerAuthData, ownerAuthLen);
      sha1_finish(ctxOwn);
    }
    else {
      memset(ctxOwn->hash,0,20);
    }

    configure(passPhrase, *lenPassphrase, ctxOwn->hash, ctxSrk->hash, ctxPas->hash);

#ifdef EXEC
            ERROR(25, tis_deactivate_all(), "tis_deactivate failed");
#else
            ERROR(25, tis_deactivate_all(), &string_literal);
#endif

#ifdef EXEC
	        out_string("\nConfiguration complete. Rebooting now...\n");
#else
	        out_string(&string_literal);
#endif

	        wait(5000);
	        reboot();
        }
        else { 
            unsealPassphrase(ctxSrk->hash, ctxPas->hash);
        }
#ifdef EXEC
        ERROR(25, tis_deactivate_all(), "tis_deactivate failed");
#else
        ERROR(25, tis_deactivate_all(), &string_literal);
#endif
    }

    memset(srkAuthData, 0, 20);
    memset(ownerAuthData, 0, 20);
    memset(passPhraseAuthData, 0, 20);

    //zero_stack();

    // cleanup
    dealloc(heap, ctx, sizeof(struct SHA1_Context));
    dealloc(heap, ctxSrk, sizeof(struct SHA1_Context));
    dealloc(heap, ctxOwn, sizeof(struct SHA1_Context));
    dealloc(heap, ctxPas, sizeof(struct SHA1_Context));
    dealloc(heap, dig, sizeof(TPM_DIGEST));
    dealloc(heap, passPhrase, 64);
    dealloc(heap, lenPassphrase, sizeof(UINT32));
    dealloc(heap, srkAuthData, 20);
    dealloc(heap, ownerAuthData, 20);
    dealloc(heap, passPhraseAuthData, 20);

#ifdef EXEC
    ERROR(27, start_module(mbi), "start module failed");
#else
    ERROR(27, start_module(mbi), &string_literal);
#endif
    return 28;
}


