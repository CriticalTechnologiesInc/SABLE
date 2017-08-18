/* hello.c - test module for dynamic loading */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2007  Free Software Foundation, Inc.
 *  Copyright (C) 2003  NIIBE Yutaka <gniibe@m17n.org>
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>
#include <multiboot.h>


/* begin crypto extension */

#include "tpm/util.c"
#include "tpm/sable_tpm.h"
#include "tpm/hmac.c"
#include "tpm/tpm_error.h"
#include "tpm/asm.h"
#include "tpm/tis.c"
#include "tpm/sha.c"
#include "tpm/tpm.c"

#include <grub/env.h>

/* end crypto extension */

#define MAX_COUNTERSIGN 192 //256(max passphrase value from luks.c) - 64(max passphrase length for SABLE)
#define MAX_SECRET 256

#define CHECK_FLAG(flags,bit) ((flags) & (1 << (bit)))

GRUB_MOD_LICENSE ("GPLv3+");

static grub_err_t
grub_cmd_hello (grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc __attribute__ ((unused)),
		char **args __attribute__ ((unused)))
{
  grub_printf ("%s\n\n", _("The new Hello World"));

	if (tis_init(TIS_BASE))
	{
		grub_printf("tis_init() success!\n");
		if (tis_access(TIS_LOCALITY_2, 0) == 0)
		{
			grub_printf("\ncould not gain TIS ownership\n");
			return GRUB_ERR_IO;
		}
		else
		{
			TPM_RESULT res;

	BYTE *in_buffer = grub_malloc(TCG_BUFFER_SIZE);
	if (in_buffer == NULL)
	{
		grub_printf("\nCould not allocate memory for 'in_buffer'\n");
		return GRUB_ERR_IO;
	}
	grub_memset(in_buffer, 0, sizeof(stTPM_PCRREAD));

	SessionCtx *sctx = grub_malloc(sizeof(SessionCtx));
	if (sctx == NULL)
	{
		grub_printf("\nCould not allocate memory for 'sctx'\n");
		grub_free(in_buffer);
		return GRUB_ERR_IO;
	}
	grub_memset(sctx, 0, sizeof(SessionCtx));
  
	SessionCtx *sctxParent = grub_malloc(sizeof(SessionCtx));
	if (sctxParent == NULL)
	{
		grub_printf("\nCould not allocate memory for 'sctxParent'\n");
		grub_free(in_buffer);
		grub_free(sctx);
		return GRUB_ERR_IO;
	}
	grub_memset(sctxParent, 0, sizeof(SessionCtx));

	SessionCtx *sctxEntity = grub_malloc(sizeof(SessionCtx));
	if (sctxEntity == NULL)
	{
		grub_printf("\nCould not allocate memory for 'sctxEntity'\n");
		grub_free(in_buffer);
		grub_free(sctx);
		grub_free(sctxParent);
		return GRUB_ERR_IO;
	}
	grub_memset(sctxEntity, 0, sizeof(SessionCtx));

	char *entry = grub_malloc(sizeof(char));
	if (entry == NULL)
	{
		grub_printf("\nCould not allocate memory for 'entry'\n");
		grub_free(in_buffer);
		grub_free(sctx);
		grub_free(sctxParent);
		grub_free(sctxEntity);
		return GRUB_ERR_IO;
	}
	grub_memset(entry, 0, sizeof(char));

	BYTE *usageAuthSRK = grub_malloc(20);	
	if (usageAuthSRK == NULL)
	{
		grub_printf("\nCould not allocate memory for 'usageAuthSRK'\n");
		grub_free(in_buffer);
		grub_free(sctx);
		grub_free(sctxParent);
		grub_free(sctxEntity);
		grub_free(entry);
		return GRUB_ERR_IO;
	}
	grub_memset(usageAuthSRK, 0, 20);

	BYTE *sealedData = grub_malloc(400);
	if (sealedData == NULL)
	{
		grub_printf("\nCould not allocate memory for 'sealedData'\n");
		grub_free(in_buffer);
		grub_free(sctx);
		grub_free(sctxParent);
		grub_free(sctxEntity);
		grub_free(entry);
		grub_free(usageAuthSRK);
		return GRUB_ERR_IO;
	}
	grub_memset(sealedData, 0, 400);

	BYTE *unsealedData = grub_malloc(100);
	if (unsealedData == NULL)
	{
		grub_printf("\nCould not allocate memory for 'unsealedData'\n");
		grub_free(in_buffer);
		grub_free(sctx);
		grub_free(sctxParent);
		grub_free(sctxEntity);
		grub_free(entry);
		grub_free(usageAuthSRK);
		grub_free(sealedData);
		return GRUB_ERR_IO;
	}
	grub_memset(unsealedData, 0, 100);

	UINT32 *unsealedDataSize = grub_malloc(sizeof(UINT32));
	if (unsealedDataSize == NULL)
	{
		grub_printf("\nCould not allocate memory for 'unsealedDataSize'\n");
		grub_free(in_buffer);
		grub_free(sctx);
		grub_free(sctxParent);
		grub_free(sctxEntity);
		grub_free(entry);
		grub_free(usageAuthSRK);
		grub_free(sealedData);
		grub_free(unsealedData);
		return GRUB_ERR_IO;
	}
	grub_memset(unsealedDataSize, 0, sizeof(UINT32));

	res = TPM_Start_OIAP(in_buffer, sctx);

	if (res != 0)
	{
		grub_printf("\nTPM_Start_OIAP error, res is %lu\n", res);
	}
	res = TPM_NV_ReadValueAuth(in_buffer, sealedData, 400, sctx);
	if (res != 0)
	{
		grub_printf("\nTPM_NV_ReadValueAuth error, res is %lu\n", res);
	}		
	res = TPM_Start_OIAP(in_buffer, sctxParent);
	if (res != 0)
	{
		grub_printf("\nTPM_Start_OIAP error (2nd), res is %lu\n", res);
	}
	res = TPM_Start_OIAP(in_buffer, sctxEntity);
	if (res != 0)
	{
		grub_printf("\nTPM_Start_OIAP error (3rd), res is %lu\n", res);
	}
	
	// Get Data Password and SRK Password from User
	char dataPass[sizeof(TPM_AUTHDATA)];
	grub_printf("Please enter the passPhraseAuthData\n");
	grub_password_get(dataPass, sizeof(TPM_AUTHDATA));
	int resData = strnlen_sable(dataPass, sizeof(TPM_AUTHDATA));
	
	char srkPass[sizeof(TPM_AUTHDATA)];
	grub_printf("Please enter the srkAuthData\n");
	grub_password_get(srkPass, sizeof(TPM_AUTHDATA));
	int resSRK = strnlen_sable(srkPass, sizeof(TPM_AUTHDATA));
	
	// SHA1 hash both passwords, and pass to TPM_Unseal
	TPM_AUTHDATA dataHash;
	TPM_AUTHDATA srkHash;
	
	grub_printf("Hashing Data Pass");
	struct SHA1_Context dctx;
	sha1_init(&dctx);
	sha1(&sctx, (BYTE *)dataPass, resData);
	sha1_finish(&dctx);
	dataHash = *(TPM_AUTHDATA *)&dctx.hash; 
	grub_printf("Hashed Data Pass");
	
	grub_printf("Hashing SRK Pass");
	struct SHA1_Context rctx;
	sha1_init(&rctx);
	sha1(&rctx, (BYTE *)srkPass, resSRK);
	sha1_finish(&rctx);
	srkHash = *(TPM_AUTHDATA *)&rctx.hash; 
	grub_printf("Hashed SRK Pass");
	
	res = TPM_Unseal(in_buffer, sealedData, unsealedData, 100, unsealedDataSize, sctxParent, sctxEntity, &dataHash, &srkHash);
	
	if (res != 0)
	{
		grub_printf("\nTPM_Unseal error, res is %lu\n", res);
	}

	grub_printf("\nThe unsealed passphrase is\n\n");
	grub_printf("passphrase: ");

	grub_printf("%s\n\n", unsealedData);

	char countersign[MAX_COUNTERSIGN] = "";

	grub_printf("\nEnter countersign: ");
	grub_password_get(countersign, MAX_COUNTERSIGN);
	grub_printf("\n");

	grub_size_t secretSize = 0;

	secretSize = (*unsealedDataSize - 1) + grub_strlen(countersign);

	grub_printf("\nSecret size is %u\n", secretSize);
	
	grub_printf("\nThe countersign you chose is %s\n", countersign);
	grub_printf("Its first letter is %c\n", countersign[1]);
//	secret = (char *)(grub_env_get("key"));

	if ( secretSize > MAX_SECRET )
	{
		grub_printf("\nMaximum secret length exceeded\n");
		goto cleanup;
	}

	char secret[MAX_SECRET] = "";
	
//	BYTE *dp = secret;
	const BYTE *sp = unsealedData;
	UINT32 i;
	for (i = 0; i < *unsealedDataSize-1 ; i++)
  {
    secret[i] = *sp;
    sp++;
  }
	for (UINT32 c = 0; c < (grub_strlen(countersign)) ; c++)
  {
		grub_printf("c is %u\n", c);
		grub_printf("i is %u\n", i);
    secret[i+c] = countersign[c];
  }

	grub_printf("\nThe secret is: '%s'", secret);
	grub_printf("\n");

cleanup:
	grub_free(in_buffer);
  grub_free(sctx);
  grub_free(sctxParent);
  grub_free(sctxEntity);
  grub_free(usageAuthSRK);
  grub_free(sealedData);
  grub_free(unsealedData);
  grub_free(unsealedDataSize);
		}
	}
	else
	{
		grub_printf("tis_init() failed");
		return GRUB_ERR_IO;
	}

  return 0;

}

static grub_extcmd_t cmd;

GRUB_MOD_INIT(hello)
{
  cmd = grub_register_extcmd ("hello", grub_cmd_hello, 0, 0,
			      N_("Say `Hello World'."), 0);
}

GRUB_MOD_FINI(hello)
{
  grub_unregister_extcmd (cmd);
}
