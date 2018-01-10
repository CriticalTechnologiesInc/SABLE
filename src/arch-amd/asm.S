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

#ifndef NDEBUG
#define STACK_TOP 0x180000
#define SLB_STACK_TOP 0x180000
#else
#define STACK_TOP 0x110000
#define SLB_STACK_TOP 0x110000
#endif

#define ALIGN_4K 0xfffff000

#define cs_sel                1<<3 /* 0x08 */
#define ds_sel                2<<3 /* 0x10 */

#define VM_CR_MSR 0xc0010114

.macro	FUNCTION name
	.section .text
	.globl \name
	\name:
.endm

FUNCTION __mbheader
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


FUNCTION do_skinit
	mov    $g_sl_begin, %eax
	skinit

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
end_gdt:
