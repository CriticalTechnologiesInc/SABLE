/*
 * tpm.c: TPM-related support functions
 *
 * Copyright (c) 2006-2010, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "platform.h"
#include "processor.h"
#include "intel_tpm.h"


/*
 * Bhushan : Adding out_* to avoid compilation errors : Move this to correct .h file
 */

/*
 * Bhushan : We should use sables tpm driver insted of tboots, so this all code should go away
 */

void out_description(const char *prefix, unsigned int value);
void out_info(const char *msg);
void memset(void *s, BYTE c, UINT32 len);
void wait(int ms);


__attribute__ ((__section__ (".data"))) struct tpm_if *g_tpm = NULL;

/* Global variables for TPM status register */
static tpm20_reg_sts_t		g_reg_sts;
static tpm12_reg_sts_t		*g_reg_sts_12 = (tpm12_reg_sts_t *)&g_reg_sts;

uint8_t g_tpm_family = 0;

/* TPM_DATA_FIFO_x */
#define TPM_REG_DATA_FIFO        0x24
typedef union {
	uint8_t _raw[1];                      /* 1-byte reg */
} tpm_reg_data_fifo_t;

#define TPM_ACTIVE_LOCALITY_TIME_OUT    \
          (TIMEOUT_UNIT * g_tpm->timeout.timeout_a)  /* according to spec */
#define TPM_CMD_READY_TIME_OUT          \
          (TIMEOUT_UNIT * g_tpm->timeout.timeout_b)  /* according to spec */
#define TPM_CMD_WRITE_TIME_OUT          \
          (TIMEOUT_UNIT * g_tpm->timeout.timeout_d)  /* let it long enough */
#define TPM_DATA_AVAIL_TIME_OUT         \
          (TIMEOUT_UNIT * g_tpm->timeout.timeout_c)  /* let it long enough */
#define TPM_RSP_READ_TIME_OUT           \
          (TIMEOUT_UNIT * g_tpm->timeout.timeout_d)  /* let it long enough */
#define TPM_VALIDATE_LOCALITY_TIME_OUT  0x100

#define read_tpm_sts_reg(locality) { \
if ( g_tpm_family == 0 ) \
    read_tpm_reg(locality, TPM_REG_STS, g_reg_sts_12); \
else \
	out_info("ERROR : TPM20 : not supported"); \
}

#define write_tpm_sts_reg(locality) { \
if ( g_tpm_family == 0 ) \
    write_tpm_reg(locality, TPM_REG_STS, g_reg_sts_12); \
else \
	out_info("ERROR : TPM20 : not supported"); \
} 

static void tpm_send_cmd_ready_status(uint32_t locality)
{
	/* write 1 to TPM_STS_x.commandReady to let TPM enter ready state */
	memset((void *)&g_reg_sts, 0, sizeof(g_reg_sts));
	g_reg_sts.command_ready = 1;
	write_tpm_sts_reg(locality);
}

static bool tpm_check_cmd_ready_status(uint32_t locality)
{
	read_tpm_sts_reg(locality);
#ifdef _DEBUG_BHUSHAN_
	out_info("tpm_check_cmd_ready_status");
#endif
	return g_reg_sts.command_ready;
}

static void tpm_print_status_register(void)
{
	if ( g_tpm_family == 0 )
	{
		out_info("TPM: status reg content:");
		out_description("BIT1", (uint32_t)g_reg_sts_12->_raw[0]);
		out_description("BIT2", (uint32_t)g_reg_sts_12->_raw[1]);
		out_description("BIT3", (uint32_t)g_reg_sts_12->_raw[2]);
	} else {
		out_info("ERROR: Unexpected");
	}
}

static u16 tpm_get_burst_count(uint32_t locality)
{
	read_tpm_sts_reg(locality);
	return g_reg_sts.burst_count;
}

static int tpm_check_expect_status(uint32_t locality)
{
	out_info("tpm_check_expect_status");
	read_tpm_sts_reg(locality);
	return g_reg_sts.sts_valid == 1 && g_reg_sts.expect == 0;
}

static int  tpm_check_da_status(uint32_t locality)
{
	out_info("tpm_check_da_status");
	read_tpm_sts_reg(locality);
	return g_reg_sts.sts_valid == 1 && g_reg_sts.data_avail == 1;
}

static void tpm_execute_cmd(uint32_t locality)
{
	memset((void *)&g_reg_sts, 0, sizeof(g_reg_sts));
	g_reg_sts.tpm_go = 1;
	write_tpm_sts_reg(locality);
}

int tpm_validate_locality(uint32_t locality)
{
	uint32_t i;
	tpm_reg_access_t reg_acc;

	for (i = TPM_VALIDATE_LOCALITY_TIME_OUT; i > 0; i--) {
		/*
		 * TCG spec defines reg_acc.tpm_reg_valid_sts bit to indicate whether
		 * other bits of access reg are valid.( but this bit will also be 1
		 * while this locality is not available, so check seize bit too)
		 * It also defines that reading reg_acc.seize should always return 0
		 */
		read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
		if (reg_acc.tpm_reg_valid_sts == 1 && reg_acc.seize == 0) {
			return 1;
		}
		cpu_relax();
	}
	if (i <= 0) {
		out_info("TPM: tpm_validate_locality timeout");
	}
	return 0;
}

bool tpm_validate_locality_crb(uint32_t locality)
{
	uint32_t i;
	tpm_reg_loc_state_t reg_loc_state;

	for ( i = TPM_VALIDATE_LOCALITY_TIME_OUT; i > 0; i-- ) {
		/*
		 *  Platfrom Tpm  Profile for TPM 2.0 SPEC
		 */
		read_tpm_reg(locality, TPM_REG_LOC_STATE, &reg_loc_state);
		if ( reg_loc_state.tpm_reg_valid_sts == 1 &&
		     reg_loc_state.loc_assigned == 1 &&
		     reg_loc_state.active_locality == locality) {
			 return true;
        	}
		cpu_relax(); 
	}
	out_info("TPM: tpm_validate_locality_crb timeout");
	return false;
}

int  tpm_wait_cmd_ready(uint32_t locality)
{
	uint32_t		i;
	tpm_reg_access_t	reg_acc;

	/* request access to the TPM from locality N */
	reg_acc._raw[0] = 0;
	reg_acc.request_use = 1;
	write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

	i = 0;
	do {
		read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
		if (reg_acc.active_locality == 1)
			break;
		else
			cpu_relax();
		i++;
	} while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT);

	if ( i > TPM_ACTIVE_LOCALITY_TIME_OUT ) {
		out_info("TPM: FIFO_INF access reg request use timeout");
		return 0;
	}

	/* ensure the TPM is ready to accept a command */
	out_info("TPM: wait for cmd ready");
	i = 0;
	do {
		tpm_send_cmd_ready_status(locality);
		cpu_relax();
		/* then see if it has */

		if (tpm_check_cmd_ready_status(locality))
			break;
		else
			cpu_relax();
		i++;
	} while ( i <= TPM_CMD_READY_TIME_OUT );
	if ( i > TPM_CMD_READY_TIME_OUT ) {
		tpm_print_status_register();
		out_info("TPM: tpm timeout for command_ready");
		goto RelinquishControl;
	}

	return 1;

RelinquishControl:
	/* deactivate current locality */
	reg_acc._raw[0] = 0;
	reg_acc.active_locality = 1;
	write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

	return 0;
}

int tpm_submit_cmd(u32 locality, u8 *in, u32 in_size,  u8 *out, u32 *out_size)
{
	u32			i, rsp_size, offset;
	u16			row_size;
	tpm_reg_access_t	reg_acc;
	int			ret = 1;

	if (locality >= TPM_NR_LOCALITIES) {
		out_info("TPM: Invalid locality for tpm_write_cmd_fifo()");
		return 0;
	}
	if (in == NULL || out == NULL || out_size == NULL) {
		out_info("TPM: Invalid parameter for tpm_write_cmd_fifo()");
		return 0;
	}
	if (in_size < CMD_HEAD_SIZE || *out_size < RSP_HEAD_SIZE) {
		out_info("TPM: in/out buf size must be larger than 10 bytes\n");
		return 0;
	}

	if (!tpm_validate_locality(locality)) {
		out_description("TPM: Locality %d is not open\n", locality);
		return 0;
	}

	if (!tpm_wait_cmd_ready(locality)) {
		return 0;
	}

	/* write the command to the TPM FIFO */
	offset = 0;
	do {
		i = 0;
		do {
			/* find out how many bytes the TPM can accept in a row */
			row_size = tpm_get_burst_count(locality);
			if (row_size > 0) {
				break;
			} else {
				cpu_relax();
			}
			i++;
		} while ( i <= TPM_CMD_WRITE_TIME_OUT );
		if ( i > TPM_CMD_WRITE_TIME_OUT ) {
			out_info("TPM: write cmd timeout");
			ret = 0;
			goto RelinquishControl;
		}

		for ( ; row_size > 0 && offset < in_size; row_size--, offset++ ) {
			write_tpm_reg(locality, TPM_REG_DATA_FIFO,  (tpm_reg_data_fifo_t *)&in[offset]);
		}
	} while (offset < in_size);

	i = 0;
	do {
		if (tpm_check_expect_status(locality)) {
			break;
		} else {
			cpu_relax();
		}
		i++;
	} while ( i <= TPM_DATA_AVAIL_TIME_OUT );
	if (i > TPM_DATA_AVAIL_TIME_OUT) {
		out_info("TPM: wait for expect becoming 0 timeout");
		ret = 0;
		goto RelinquishControl;
	}

	/* command has been written to the TPM, it is time to execute it. */
	tpm_execute_cmd(locality);

	/* check for data available */
	i = 0;
	do {
		if (tpm_check_da_status(locality))  break;
		else  cpu_relax();
		i++;
	} while ( i <= TPM_DATA_AVAIL_TIME_OUT );
	if (i > TPM_DATA_AVAIL_TIME_OUT) {
		out_info("TPM: wait for data available timeout");
		ret = 0;
		goto RelinquishControl;
	}

	rsp_size = 0;
	offset = 0;
	do {
		/* find out how many bytes the TPM returned in a row */
		i = 0;
		do {
			row_size = tpm_get_burst_count(locality);
			if ( row_size > 0 )  break;
			else cpu_relax();
			i++;
		} while (i <= TPM_RSP_READ_TIME_OUT);
		if (i > TPM_RSP_READ_TIME_OUT ) {
			out_info("TPM: read rsp timeout\n");
			ret = 0;
			goto RelinquishControl;
		}

		for ( ; row_size > 0 && offset < *out_size; row_size--, offset++ ) {
			if (offset < *out_size) {
				read_tpm_reg(locality, TPM_REG_DATA_FIFO, (tpm_reg_data_fifo_t *)&out[offset]);
			} else {
				/* discard the responded bytes exceeding out buf size */
				tpm_reg_data_fifo_t discard;
				read_tpm_reg(locality, TPM_REG_DATA_FIFO,  (tpm_reg_data_fifo_t *)&discard);
			}

			/* get outgoing data size */
			if ( offset == RSP_RST_OFFSET - 1 ) {
				reverse_copy(&rsp_size, &out[RSP_SIZE_OFFSET], sizeof(rsp_size));
			}
		}
	} while ( offset < RSP_RST_OFFSET || (offset < rsp_size && offset < *out_size) );
	*out_size = (*out_size > rsp_size) ? rsp_size : *out_size;
	tpm_send_cmd_ready_status(locality);

RelinquishControl:
	/* deactivate current locality */
	reg_acc._raw[0] = 0;
	reg_acc.active_locality = 1;
	write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

	return ret;
}

int release_locality(uint32_t locality)
{
	uint32_t i;

	out_description("TPM: releasing locality :", locality);
	out_description("Bhushan: for measured launch we should be in locality :", locality);

	if (!tpm_validate_locality(locality)) {
		return 1;
	}

	tpm_reg_access_t reg_acc;
	read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
	if (reg_acc.active_locality == 0) {
		return 1;
	}

	/* make inactive by writing a 1 */
	reg_acc._raw[0] = 0;
	reg_acc.active_locality = 1;
	write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

	i = 0;
	do {
		read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
		if (reg_acc.active_locality == 0)
			return 1;
		else
			cpu_relax();
		i++;
	} while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT );

	out_info("TPM: access reg release locality timeout");
	return 0;
}

int tpm_relinquish_locality_crb(uint32_t locality)
{
	uint32_t i;
	tpm_reg_loc_state_t reg_loc_state;
	tpm_reg_loc_ctrl_t reg_loc_ctrl;

	if ( !tpm_validate_locality_crb(locality) )
		return 1;
	read_tpm_reg(locality, TPM_REG_LOC_STATE, &reg_loc_state);
	if ( reg_loc_state.loc_assigned == 0 )
		return 1;

	/* make inactive by writing a 1 */
	memset(&reg_loc_ctrl,0,sizeof(reg_loc_ctrl));
	reg_loc_ctrl.relinquish = 1;
	write_tpm_reg(locality, TPM_REG_LOC_CTRL, &reg_loc_ctrl);

	i = 0;
	do {
		read_tpm_reg(locality, TPM_REG_LOC_STATE, &reg_loc_state);
		if ( reg_loc_state.loc_assigned == 0 )
			return 1;
		else 
			cpu_relax();
		i++;
	} while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT );

	out_info("TPM: CRB_INF release locality timeout");
	return 0;
}

int is_tpm_crb(void)
{      
	tpm_crb_interface_id_t crb_interface;
	read_tpm_reg(0, TPM_INTERFACE_ID, &crb_interface);
	if (crb_interface.interface_type == TPM_INTERFACE_ID_CRB  ) {
		out_info("TPM: PTP CRB interface is active...");
	if (g_tpm_family != TPM_IF_20_CRB ) g_tpm_family = TPM_IF_20_CRB;
		return 1;
	}
	if (crb_interface.interface_type == TPM_INTERFACE_ID_FIFO_20) {
		out_info("TPM: TPM 2.0 FIFO interface is active...\n");     
		if (g_tpm_family != TPM_IF_20_FIFO) g_tpm_family = TPM_IF_20_FIFO;
	}
	return 0;	
}

int prepare_tpm_intel(void)
{
	/*
	 * must ensure TPM_ACCESS_0.activeLocality bit is clear
	 * (: locality is not active)
	 */

	if (is_tpm_crb()) {
		out_info("BHUSHAN : DEBUG: Are we suppose to be here?");
		return true;
	} else { 
		out_info("BHUSHAN: we are going to prepare TPM");
		return release_locality(0);
	}
}

int tpm_request_locality_crb(uint32_t locality){
	uint32_t            i;
	tpm_reg_loc_state_t  reg_loc_state;
	tpm_reg_loc_ctrl_t    reg_loc_ctrl;
	/* request access to the TPM from locality N */
	memset(&reg_loc_ctrl,0,sizeof(reg_loc_ctrl));
	reg_loc_ctrl.requestAccess = 1;
	write_tpm_reg(locality, TPM_REG_LOC_CTRL, &reg_loc_ctrl);

	i = 0;
	do {
		read_tpm_reg(locality, TPM_REG_LOC_STATE, &reg_loc_state);
		if ( reg_loc_state.active_locality == locality && reg_loc_state.loc_assigned == 1)
			break;
		else
			cpu_relax();
		i++;
	} while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT);

	if ( i > TPM_ACTIVE_LOCALITY_TIME_OUT ) {
		out_info("TPM: access loc request use timeout");
		return 0;
	}
	return 1;
}

int tpm_detect(void)
{
	if (is_tpm_crb()) {
		out_info("ERROR : we dont support this configuration");
	}
	else {
		g_tpm = &tpm_12_if; /* Don't leave g_tpm as NULL*/
		if (tpm_validate_locality(0)) {
			out_info("TPM: FIFO_INF Locality 0 is open");
		} else {	
			out_info("TPM: FIFO_INF Locality 0 is not open");
			return 0;
		}
		out_info("tpm_detect: Ok till now");
		/* determine TPM family from command check */
		if (g_tpm->check())  {
			g_tpm_family = TPM_IF_12;
			out_description("TPM: discrete TPM1.2 Family", g_tpm_family);	
		} else {
			g_tpm_family = TPM_IF_20_FIFO;
			out_description("ERROR: TPM: discrete TPM2.0 Family", g_tpm_family);
			return 0;
		}
		out_info("TPM1_2 check : Done");
	}

	if (g_tpm_family == TPM_IF_12)  g_tpm = &tpm_12_if;
	return g_tpm->init(g_tpm);
}
