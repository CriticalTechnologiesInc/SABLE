#include "util.h"
#include "processor.h"
#include "types.h"
#include "msr.h"
#include "smx.h"

static unsigned long g_feat_ctrl_msr;
static unsigned int g_cpuid_ext_feat_info;

static int read_processor_info(void)
{
	unsigned long f1, f2;
 	/* eax: regs[0], ebx: regs[1], ecx: regs[2], edx: regs[3] */
	uint32_t regs[4];

	/* is CPUID supported? */
	/* (it's supported if ID flag in EFLAGS can be set and cleared) */
	asm("pushf\n\t"
	    "pushf\n\t"
	    "pop %0\n\t"
	    "mov %0,%1\n\t"
	    "xor %2,%0\n\t"
 	    "push %0\n\t"
 	    "popf\n\t"
	    "pushf\n\t"
	    "pop %0\n\t"
	    "popf\n\t"
	    : "=&r" (f1), "=&r" (f2)
	    : "ir" (X86_EFLAGS_ID));
	    if (((f1^f2) & X86_EFLAGS_ID) == 0) {
		g_cpuid_ext_feat_info = 0;
		out_info("CPUID instruction is not supported");
	    return 0;
	}

	do_cpuid(0, regs);
	if (regs[1] != 0x756e6547        /* "Genu" */
	    || regs[2] != 0x6c65746e     /* "ntel" */
	    || regs[3] != 0x49656e69 ) { /* "ineI" */
		g_cpuid_ext_feat_info = 0;
		out_info("Non-Intel CPU detected");
		return 0;
	}
	g_cpuid_ext_feat_info = cpuid_ecx(1);

	/* read feature control msr only if processor supports VMX or SMX instructions */
	if ((g_cpuid_ext_feat_info & CPUID_X86_FEATURE_VMX) ||
	    (g_cpuid_ext_feat_info & CPUID_X86_FEATURE_SMX)) {
		g_feat_ctrl_msr = rdmsr(MSR_IA32_FEATURE_CONTROL);
		out_description("IA32_FEATURE_CONTROL_MSR:", g_feat_ctrl_msr);
	}
	return 1;
}


static int supports_smx(void)
{
	/* check that processor supports SMX instructions */
	if (!(g_cpuid_ext_feat_info & CPUID_X86_FEATURE_SMX)) {
		out_info("CPU does not support SMX");
		return 0;
	}
	out_info("CPU is SMX-capable\n");

	/*
	 * and that SMX is enabled in the feature control MSR
	 */

	/* check that the MSR is locked -- BIOS should always lock it */
	if (!(g_feat_ctrl_msr & IA32_FEATURE_CONTROL_MSR_LOCK) ) {
		out_info("ERR: IA32_FEATURE_CONTROL_MSR_LOCK is not locked\n");
		/* this should not happen, as BIOS is required to lock the MSR */
		/* we enable VMX outside of SMX as well so that if there was some */
		return 0;
	}

	/* check that SENTER (w/ full params) is enabled */
	if (!(g_feat_ctrl_msr & (IA32_FEATURE_CONTROL_MSR_ENABLE_SENTER |
			IA32_FEATURE_CONTROL_MSR_SENTER_PARAM_CTL)) ) {
		out_description("ERR: SENTER disabled by feature control MSR", g_feat_ctrl_msr);
		return 0;
	}

	return 1;
}

static int supports_vmx(void)
{
	/* check that processor supports VMX instructions */
	if (!(g_cpuid_ext_feat_info & CPUID_X86_FEATURE_VMX)) {
		out_info("ERR: CPU does not support VMX");
		return 0;
	}
	out_info("CPU is VMX-capable");

	/* and that VMX is enabled in the feature control MSR */
	if (!(g_feat_ctrl_msr & IA32_FEATURE_CONTROL_MSR_ENABLE_VMX_IN_SMX) ) {
		out_description("ERR: VMXON disabled by feature control MSR", g_feat_ctrl_msr);
		return 0;
	}
	return 1;
}

int supports_txt(void)
{
	capabilities_t cap;

	/* processor must support cpuid and must be Intel CPU */
	if (!read_processor_info()) {
		out_info("non Intel or non supported CPU");
		return 0;
	}

	/* processor must support SMX */
	if (!supports_smx()) {
		out_info("SMX not supported");
		return 0;
	}

	if (!supports_vmx()) {
		out_info("VMX not supported");
		return 0;
	}
 
	/* testing for chipset support requires enabling SMX on the processor */
	write_cr4(read_cr4() | CR4_SMXE);
	out_info("SMX is enabled\n");
 
	/*
	 * verify that an TXT-capable chipset is present and
	 * check that all needed SMX capabilities are supported
	 */

	cap = __getsec_capabilities(0);
	if (cap.chipset_present) {
		if (cap.senter && cap.sexit && cap.parameters && cap.smctrl && cap.wakeup) {
			out_info("TXT chipset and all needed capabilities present");
			return 1;
		}
		else
		out_description("ERR: insufficient SMX capabilities", cap._raw);
	} else {
		out_info("ERR: TXT-capable chipset not present");
	}
	/* since we are failing, we should clear the SMX flag */
	write_cr4(read_cr4() & ~CR4_SMXE);

	return 0;
}

int platform_pre_checks() {
	/* need to verify that platform supports TXT before we can check error */	
	if (!supports_txt()) {
		out_info("ERROR: supports_txt");
		return 0;
	}
	return 1;
}
