/*
 * \brief   ASM functions like do_skinit or reboot.
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

/**
 * Fixup the state of the application processors after skint. This
 * should be done in the linux kernel...
 */

#define MBI_MAGIC1 0x1BADB002
#define MBI_MAGIC2 0x2BADB002

#define STACK_TOP 0x180000
#define SLB_STACK_TOP 0x180000
#define ALIGN_4K 0xfffff000

#define cs_sel                1<<3 /* 0x08 */
#define ds_sel                2<<3 /* 0x10 */


/* OsSinitData field offsets */
#define TXT_PRIV_CONFIG_REGS_BASE	0xfed20000
#define TXTCR_HEAP_BASE			0x0300
#define MLE_PGTBL_OFF			8

/* From http://fxr.watson.org/fxr/source/i386/include/param.h */
#define PAGE_SHIFT       12                 /* LOG2(PAGE_SIZE) */
#define PAGE_SIZE        (1 << PAGE_SHIFT)  /* bytes/page */
/* PAGE_MASK is used to pass bits 12 and above. */
#define PAGE_MASK        (~(PAGE_SIZE-1))


#define NR_CPUS		512
#define AP_STACK_SIZE	0x0800

#define VM_CR_MSR 0xc0010114

.macro	FUNCTION name
	.section .text
	.globl \name
	\name:
.endm

.section ".tboot_multiboot_header","w"
	.align  4, 0x90
	.long   MBI_MAGIC1              /* magic */
	.long   0x00000003              /* feature flags */
	.long   0 - (MBI_MAGIC1 + 0x3)

FUNCTION __start
	leal    STACK_TOP,%esp
	xchg    %eax,%edx
	xchg    %ebx,%eax
	pushl	%eax
	pushl   $exit
	jmp     _pre_launch

/* Bhushan _post_launch_entry is just place holder. we have to provide implementation when required */

FUNCTION _post_launch_entry

/* entry point post-launch, to verify memory layout */
/* (must all be w/in one page; since _start is page-aligned, it will be; */
/* which is why we can't call much other code (e.g. printk, TPM fns, etc.) */
/* verify phys addr we were entered at is the one we expected
 * ebx contains the phys addr of the entry point
 * ecx contains the phy addr of the MLE page table
 */
	/*
	 cmp $_post_launch_entry, %ebx
	jne layout_err
	*/

	/* verify last entry in MLE page table is the one we expected
	 * this is sufficient because: 1) all addrs must be phys increasing
	 * and 2) tboot is phys contig--therefore if any page were moved to
	 * a different phys addr then the last page would have to be different
	 * from tboot's last page
	 */
	 /* get addr of MLE page table from OsSinitData */
	/* start of TXT heap (== BiosDataSize) */
	mov (TXT_PRIV_CONFIG_REGS_BASE + TXTCR_HEAP_BASE), %eax
	add (%eax), %eax                   /* skip BiosData */
	add (%eax), %eax                   /* skip OsMleData */
	mov (MLE_PGTBL_OFF+8)(%eax), %eax  /* addr of MLE page table */
	/* get to page table itself (there is only one for tboot) */
	mov (%eax), %eax          /* pgdir ptr -> pgdir */
	/* TODO when SINIT ready */
	/* mov (%ecx), %eax */
	and $PAGE_MASK, %eax
	mov (%eax), %eax          /* pgdir -> pgtbl */
	and $PAGE_MASK, %eax
	/* find last page (pte) */
	mov $_mle_end, %ecx
	sub $_mle_start, %ecx     /* size of MLE */
	shr $PAGE_SHIFT-3, %ecx
	sub $8, %ecx              /* size/4k*8 is offset+1 of last pte */
	add %ecx, %eax
	mov (%eax), %eax          /* pte of last page */
	and $PAGE_MASK, %eax
	/* calc expected addr of last page */
	mov $(_mle_end - 1), %ebx /* addr of last byte of MLE... */
	and $PAGE_MASK, %ebx      /* ...rounded to page start */
	/* are they equal? */
	// cmp %ebx, %eax
	// je __start                /* yes, so continue with normal launch */

	/* copied from amd post lauch */

	/* Setup ESP to top of 64K */
	leal SLB_STACK_TOP, %esp

//	/* clear VM_CR to enable debugging */
//	mov     $VM_CR_MSR, %ecx
//	rdmsr
//	and     $0xf8, %al
//	wrmsr

	/* init gdt and segment register */
	lgdt    %cs:pgdt_desc
	movw    $ds_sel, %ax
	mov	%ax,   %ds
	mov	%ax,   %es
	mov	%ax,   %fs
	mov	%ax,   %gs
	mov	%ax,   %ss

	jmp __start

FUNCTION _txt_wakeup

	/*
	 * entry point for GETSEC[WAKEUP]
	 */


//	leal    STACK_TOP,%esp
//	xchg    %eax,%edx
//	xchg    %ebx,%eax
//	pushl	%eax
//	pushl   $exit
//	jmp     _pre_launch



	# prepare this thread for C code
	/* Set up a few descriptors: on entry only CS is guaranteed good. */
	lgdt    %cs:pgdt_desc
	mov     $0x10, %ecx
	mov     %ecx, %ds
	mov     %ecx, %es
	mov     %ecx, %fs
	mov     %ecx, %gs
	mov     %ecx, %ss
//	ljmp    $(cs_sel), $(1f)
	
	/* Load IDT */
//1:	lidt    idt_descr

	/* enable MCE Machine-check exception */
//	mov     %cr4,%eax
//	or      $CR4_MCE,%eax
//	mov     %eax,%cr4

	# get initial 32-bit local APIC ID for this processor
	mov     $0x0b, %eax
	xor     %edx, %edx
	cpuid

	# set stack as id-based offset from AP stack base
	# spin hlt if we exceed, since C code can't handle shared stack
	cmp     $NR_CPUS, %edx
	jl      3f
	# TBD: increment global counter so BSP can tell we exceeded NR_CPUS
2:	cli
	hlt
	jmp     2b
3:	mov     $AP_STACK_SIZE, %eax
	mul     %edx
	mov     $ap_stacks, %ecx
	sub     %eax, %ecx
	mov     %ecx, %esp

	call    txt_cpu_wakeup

FUNCTION smp_init_start
	.code16

	// Note: we could test here, whether the AP processor also
	// supports SVM, this is currently unneeded since only SVM
	// enabled processors could be on one board

	// enable svm
	mov     $0xc0000080, %ecx
	rdmsr
	or	$0x10, %ah
	wrmsr

	// clear VM_CR
	movl $VM_CR_MSR, %ecx
	rdmsr
	and  $0xf8, %al
	wrmsr


	// enable GIF - the instruction is only recognized in protected mode
	mov	$1, %ax
	lmsw	%ax
	cli
	stgi

	// halt CPU
	hlt
	.code32
	.global smp_init_end

smp_init_end:


FUNCTION reboot
	mov	$0x4, %al
	outb	%al, $0x60
	mov	$0xFE, %al
	outb	%al, $0x64
	lidt    dummy_idt_desc
	ud2
       .bss
dummy_idt_desc:
	.space 8



FUNCTION jmp_multiboot
	xchg %eax, %ebx
	mov $MBI_MAGIC2, %eax
	jmp *%edx


FUNCTION _skinit
    /* Setup ESP to top of 64K */
    leal SLB_STACK_TOP, %esp

	/* clear VM_CR to enable debugging */
 	mov     $VM_CR_MSR, %ecx
	rdmsr
	and     $0xf8, %al
	wrmsr

	/* init gdt and segment register */
	lgdt    %cs:pgdt_desc
	movw    $ds_sel, %ax
	mov	%ax,   %ds
	mov	%ax,   %es
	mov	%ax,   %fs
	mov	%ax,   %gs
	mov	%ax,   %ss

    /* restore stack and MBI header */
	leal    STACK_TOP,%esp
	movl	-4(%esp), %eax

	/* jmp to main */
	jmp     _post_launch


/* the gdt to load after skinit */
.align(8)
FUNCTION gdt
	.global pgdt_desc
	.align(8)
pgdt_desc:
	.word end_gdt - gdt - 1
	.long gdt
	.word 0
_gdt_cs:
    .quad 0x00cf9b000000ffff
_gdt_ds:
    .quad 0x00cf93000000ffff
FUNCTION end_gdt
/* end_gdt: */
/* Bhushan : I have change end_gdt: -> FUNTION edg_gdt */ 

/* stacks for APs */

ap_stacks_end:
	.fill AP_STACK_SIZE * NR_CPUS, 1, 0
ap_stacks: 

