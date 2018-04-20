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

/* opcode prefixes for 16bit data and addressing */
#define DATA16      .byte 0x66
#define ADDR16      .byte 0x67

#define STACK_TOP 0x180000
#define SLB_STACK_TOP 0x180000
#define ALIGN_4K 0xfffff000
#define BSP_STACK_SIZE		0x2000

#define cs_sel                1<<3 /* 0x08 */
#define ds_sel                2<<3 /* 0x10 */
#define cs16_sel    4<<3
#define ds16_sel    5<<3


#define TBOOT_START 0x0804000
#define CR4_MCE 0x00000040

/* From http://fxr.watson.org/fxr/source/i386/include/param.h */
#define PAGE_SHIFT       12                 /* LOG2(PAGE_SIZE) */
#define PAGE_SIZE        (1 << PAGE_SHIFT)  /* bytes/page */
/* PAGE_MASK is used to pass bits 12 and above. */
#define PAGE_MASK        (~(PAGE_SIZE-1))


#define NR_CPUS		16
#define AP_STACK_SIZE	0x0800

#define VM_CR_MSR 0xc0010114

.macro	FUNCTION name
	.section .text
	.globl \name
	\name:
.endm

#define ENTRY(name)                             \
  .globl name;                                  \
  .align 16,0x90;                               \
  name:

.section ".tboot_multiboot_header","w"
	.align  4, 0x90
	.long   MBI_MAGIC1              /* magic */
	.long   0x00000003              /* feature flags */
	.long   0 - (MBI_MAGIC1 + 0x3)

FUNCTION start
FUNCTION _start
	jmp __start

FUNCTION __start
	leal    STACK_TOP,%esp
	xchg    %eax,%edx
	xchg    %ebx,%eax
	pushl   %eax
	pushl   $exit
	jmp     _pre_launch

/*
 * vmexit handler
 */
ENTRY(vmx_asm_vmexit_handler)
        call vmx_vmexit_handler
	/* fall through to loop if callee returns (shouldn't happen) */

ENTRY(_mini_guest)
1:	pause
	cmp $0, (aps_exit_guest)
	je 1b
	/* VMCALL out of guest */
	.byte 0x0f,0x01,0xc1
	jmp 1b

#include "shutdown.S"

/*
 * entry point for GETSEC[WAKEUP]
 */
ENTRY(_txt_wakeup)
	# prepare this thread for C code
        /* Set up a few descriptors: on entry only CS is guaranteed good. */
        lgdt    %cs:pgdt_desc
        mov     $0x10, %ecx
        mov     %ecx, %ds
        mov     %ecx, %es
        mov     %ecx, %fs
        mov     %ecx, %gs
        mov     %ecx, %ss
        ljmp    $(cs_sel), $(1f)

       /* Load IDT */
1:	lidt    idt_descr

        /* enable MCE */
        mov     %cr4,%eax
        or      $CR4_MCE,%eax
        mov     %eax,%cr4

	# get initial 32-bit local APIC ID for this processor
	mov	$0x0b, %eax
	xor	%edx, %edx
	cpuid

	# set stack as id-based offset from AP stack base
	# spin hlt if we exceed, since C code can't handle shared stack
	cmp	$NR_CPUS, %edx
	jl      3f
      # TBD: increment global counter so BSP can tell we exceeded NR_CPUS
2:	cli
	hlt
	jmp     2b
3:	mov     $AP_STACK_SIZE, %eax
	mul	%edx
	mov	$ap_stacks, %ecx
	sub	%eax, %ecx
	mov	%ecx, %esp

	call	txt_cpu_wakeup


/*
 * entry point for switch to real mode and jump
 * entry point in %ebx
 */
ENTRY(_prot_to_real)
	/* disable interrupts */
	cli
	mov     0x4(%esp), %ebx

	/* deal with parameter, real mode program entry point */
	mov     %ebx, %eax
	and     $0xffff0, %eax
	shr     $4, %eax
	mov     %ax, _real_mode_entry_point + 4
	and     $0xfff0000f, %ebx
	mov     %ebx, _real_mode_entry_point

	/* load proper segments for real mode */
	mov     $(ds16_sel), %ax
	mov     %ax, %ds
	mov     %ax, %es
	mov     %ax, %fs
	mov     %ax, %gs
	mov     %ax, %ss
	lidt    real_idt_desc
	xor     %eax, %eax
	ljmp    $(cs16_sel), $(1f)

	.code16
1:	mov     %eax, %cr0
	mov     $0x0, %ax
	mov     %ax, %ds
	mov     %ax, %es
	mov     %ax, %fs
	mov     %ax, %gs
	mov     %ax, %ss

	.code32

	DATA16
	ADDR16
	ljmp    *_real_mode_entry_point

FUNCTION _skinit
	/* Set up a few descriptors: on entry only CS is guaranteed good. */
	lgdt    %cs:pgdt_desc
	mov     $(ds_sel),%ecx
	mov     %ecx,%ds
	mov     %ecx,%es
	mov     %ecx,%fs
	mov     %ecx,%gs
	mov     %ecx,%ss
	ljmp    $(cs_sel),$(1f)

	/* restore stack and MBI header */
1:	leal	STACK_TOP,%esp
	movl    -4(%esp), %eax	

	jmp _post_launch

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


/*
 * interrupt handler
 */

int_handler:
	call handle_exception
	ud2

/*
 * descriptors and descriptor tables
 */

	.align 8

/* GDT */
pgdt_desc:
	.word	end_gdt - gdt - 1
	.long	gdt

        .align PAGE_SIZE, 0

ENTRY(gdt)
		/* unused */
        .quad	0x0000000000000000
cs_descr:	/* cs */
	.word	0xffff		/* limit = 4GB */
	.word	0x00		/* base = 0 */
	.word	0x9b00		/* read + exec + accessed */
	.word	0x00cf		/* granularity = 4096 */
ds_descr:	/* ds */
	.word	0xffff		/* limit = 4GB */
	.word	0x00		/* base = 0 */
	.word	0x9300		/* read + write + accessed */
	.word	0x00cf		/* granularity = 4096 */
tss_descr:	/* tss */
	.word	0xffff		/* limit = 4GB */
	.word	0x00		/* base = 0 */
	.word	0x8900		/* system segment, 32b available TSS */
	.word	0x008f		/* granularity = 4096 */
cs16_desc:	/* cs16 */
	.word	0xffff		/* limit = 4GB */
	.word   0x0000      /* base = 0 */
	.word   0x9b00      /* read + exec + accessed */
	.word	0x008f      /* granularity = 4096, D = 0 */
ds16_desc:  /* ds16 */
	.word   0xffff      /* limit = 4GB */
	.word   0x0000      /* base = 0 */
	.word   0x9300      /* read + exec + accessed */
	.word   0x008f      /* granularity = 4096, D = 0 */
		/* end (unused) */
	.quad   0x0000000000000000
ENTRY(end_gdt)

/* GDT */
//.align(8)
//FUNCTION gdt
//        .global pgdt_desc
//        .align(8)
//pgdt_desc:
//        .word end_gdt - gdt - 1
//        .long gdt
//        .word 0
//_gdt_cs:
//    .quad 0x00cf9b000000ffff
//_gdt_ds:
//    .quad 0x00cf93000000ffff
//tss_descr:	/* tss */
//	.word	0xffff		/* limit = 4GB */
//	.word	0x00		/* base = 0 */
//	.word	0x8900		/* system segment, 32b available TSS */
//	.word	0x008f		/* granularity = 4096 */
//cs16_desc:	/* cs16 */
//	.word	0xffff		/* limit = 4GB */
//	.word   0x0000      /* base = 0 */
//	.word   0x9b00      /* read + exec + accessed */
//	.word	0x008f      /* granularity = 4096, D = 0 */
//ds16_desc:  /* ds16 */
//	.word   0xffff      /* limit = 4GB */
//	.word   0x0000      /* base = 0 */
//	.word   0x9300      /* read + exec + accessed */
//	.word   0x008f      /* granularity = 4096, D = 0 */
//		/* end (unused) */
//	.quad   0x0000000000000000
//FUNCTION end_gdt

/* Bhushan : I have change end_gdt: -> FUNTION edg_gdt */ 
/* IDT */
idt_descr:
	.word	idt_table_end - idt_table - 1
	.long	idt_table

	.align	8

idt_table:
	.rept 18
		.word	int_handler - _start
		.word	cs_sel
		.word	0x8e00   /* present, DPL=0, 32b, interrupt */
		.word	(int_handler - _start + TBOOT_START) >> 16
	.endr
	/* for machine-check exception */
		.word	int_handler - _start
		.word	cs_sel
		.word	0x8f00   /* present, DPL=0, 32b, trap */
		.word	(int_handler - _start + TBOOT_START) >> 16
	.rept 237
		.word	int_handler - _start
		.word	cs_sel
		.word	0x8e00   /* present, DPL=0, 32b, interrupt */
		.word	(int_handler - _start + TBOOT_START) >> 16
	.endr
idt_table_end:

/* Real Mode IDT */
real_idt_desc:
	.word   0x03ff
	.long   0

#include "wakeup.S"


/*
 * stacks 
 */

.section ".bss.stack_aligned","w"

bsp_stack_end:
	.fill BSP_STACK_SIZE, 1, 0
bsp_stack:

ap_stacks_end:
	.fill AP_STACK_SIZE * NR_CPUS, 1, 0
ap_stacks: 

/*
 * page table and VMCS data for AP bringup
 */

        .align PAGE_SIZE, 0
.section ".bss.page_aligned","w"
ENTRY(idle_pg_table)
        .fill 1*PAGE_SIZE,1,0

        .align PAGE_SIZE, 0
ENTRY(host_vmcs)
        .fill 1*PAGE_SIZE,1,0

        .align PAGE_SIZE, 0
/* the input info when os/vmm kerneltrap into tboot */
ENTRY(ap_vmcs)
        .fill NR_CPUS * PAGE_SIZE, 1, 0


/*
 * misc. bss data
 */
.section ".bss"

_real_mode_entry_point:
	.long   0
	.word   0

.section ".data"

ENTRY(s3_flag)
	.long 0

/*
 * shared data page with kernel (i.e. Xen)
 * (put at end so that not split e820 region for tboot)
 */
.section ".tboot_shared","w"
        .align PAGE_SIZE, 0

ENTRY(_tboot_shared)
	.fill	PAGE_SIZE,1,0
        .align PAGE_SIZE, 0

ENTRY(_end)
