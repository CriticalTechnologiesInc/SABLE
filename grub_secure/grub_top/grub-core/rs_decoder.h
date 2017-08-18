	.file	"reed_solomon.c"
	.section	.text.unlikely,"ax",@progbits
.LCOLDB0:
	.text
.LHOTB0:
	.type	pol_evaluate, @function
pol_evaluate:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%edi
	pushl	%esi
	pushl	%ebx
	movl	%eax, %esi
	movl	%ecx, %edi
	xorl	%ebx, %ebx
	xorl	%eax, %eax
.L2:
	testl	%edx, %edx
	js	.L11
	movzbl	(%esi,%edx), %ecx
	testb	%cl, %cl
	je	.L3
	movzbl	1049088(%ecx), %ecx
	xorb	1048576(%ebx,%ecx), %al
.L3:
	addl	%edi, %ebx
	cmpl	$254, %ebx
	jle	.L4
	subl	$255, %ebx
.L4:
	decl	%edx
	jmp	.L2
.L11:
	popl	%ebx
	popl	%esi
	popl	%edi
	popl	%ebp
	ret
	.size	pol_evaluate, .-pol_evaluate
	.section	.text.unlikely
.LCOLDE0:
	.text
.LHOTE0:
	.section	.text.unlikely
.LCOLDB1:
	.text
.LHOTB1:
	.type	gf_mul, @function
gf_mul:
	pushl	%ebp
	movl	%esp, %ebp
	testb	%dl, %dl
	je	.L14
	testb	%al, %al
	je	.L14
	movzbl	%al, %eax
	movzbl	1049088(%eax), %ecx
	movzbl	%dl, %edx
	movzbl	1049088(%edx), %eax
	movb	1048576(%ecx,%eax), %al
	jmp	.L13
.L14:
	xorl	%eax, %eax
.L13:
	popl	%ebp
	ret
	.size	gf_mul, .-gf_mul
	.section	.text.unlikely
.LCOLDE1:
	.text
.LHOTE1:
	.section	.text.unlikely
.LCOLDB2:
	.text
.LHOTB2:
	.type	gauss_solve.constprop.2, @function
gauss_solve.constprop.2:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%edi
	pushl	%esi
	pushl	%ebx
	subl	$36, %esp
	movl	%eax, -28(%ebp)
	movl	%edx, -16(%ebp)
	movl	%ecx, -32(%ebp)
	xorl	%eax, %eax
.L17:
	cmpl	-28(%ebp), %eax
	jge	.L45
	movl	$-1, 1049344(,%eax,4)
	incl	%eax
	jmp	.L17
.L45:
	xorl	%eax, %eax
.L19:
	cmpl	-16(%ebp), %eax
	jge	.L46
	movl	-32(%ebp), %edx
	movb	$0, (%edx,%eax)
	incl	%eax
	jmp	.L19
.L46:
	movl	-16(%ebp), %eax
	incl	%eax
	movl	%eax, -24(%ebp)
	xorl	%edi, %edi
	movl	$0, -20(%ebp)
	movl	%eax, -44(%ebp)
.L21:
	movl	-20(%ebp), %ecx
	cmpl	%ecx, -28(%ebp)
	jle	.L47
	xorl	%ebx, %ebx
.L33:
	cmpl	%ebx, -16(%ebp)
	jg	.L22
.L26:
	cmpl	%ebx, -16(%ebp)
	jne	.L43
	jmp	.L23
.L22:
	cmpb	$0, 1052672(%ebx,%edi)
	jne	.L26
	incl	%ebx
	jmp	.L33
.L23:
	incl	-20(%ebp)
	addl	-24(%ebp), %edi
	jmp	.L21
.L43:
	movl	-20(%ebp), %eax
	movl	%ebx, 1049344(,%eax,4)
	movzbl	1052672(%ebx,%edi), %eax
	movzbl	1049088(%eax), %eax
	movl	$255, %edx
	subl	%eax, %edx
	xorl	%esi, %esi
	movzbl	1048576(%edx), %eax
	movl	%eax, -36(%ebp)
.L27:
	cmpl	%esi, -16(%ebp)
	jl	.L48
	movzbl	1052672(%esi,%edi), %eax
	movl	-36(%ebp), %edx
	call	gf_mul
	movb	%al, 1052672(%esi,%edi)
	incl	%esi
	jmp	.L27
.L48:
	movl	-20(%ebp), %eax
	incl	%eax
	movl	%eax, -36(%ebp)
	movl	-24(%ebp), %eax
	leal	(%edi,%eax), %ecx
.L29:
	movl	-36(%ebp), %edx
	cmpl	%edx, -28(%ebp)
	je	.L23
	xorl	%esi, %esi
	movzbl	1052672(%ebx,%ecx), %eax
	movl	%eax, -40(%ebp)
.L30:
	cmpl	%esi, -16(%ebp)
	jl	.L49
	movl	%ecx, -48(%ebp)
	movzbl	1052672(%esi,%edi), %eax
	movl	-40(%ebp), %edx
	call	gf_mul
	movl	-48(%ebp), %ecx
	xorb	%al, 1052672(%esi,%ecx)
	incl	%esi
	jmp	.L30
.L49:
	incl	-36(%ebp)
	addl	-44(%ebp), %ecx
	jmp	.L29
.L47:
	movl	-28(%ebp), %esi
	decl	%esi
	movl	-16(%ebp), %eax
	notl	%eax
	movl	%eax, -28(%ebp)
	movl	-24(%ebp), %ebx
	imull	%esi, %ebx
	addl	-16(%ebp), %ebx
.L34:
	testl	%esi, %esi
	js	.L50
	movl	1049344(,%esi,4), %eax
	movl	%eax, -20(%ebp)
	incl	%eax
	je	.L35
	movl	%ebx, %eax
	subl	-16(%ebp), %eax
	movl	%eax, -24(%ebp)
	xorl	%edi, %edi
	xorl	%ecx, %ecx
.L36:
	cmpl	%ecx, -16(%ebp)
	jle	.L51
	movl	-32(%ebp), %eax
	movzbl	(%eax,%ecx), %edx
	movl	-24(%ebp), %eax
	movzbl	1052672(%ecx,%eax), %eax
	movl	%ecx, -36(%ebp)
	call	gf_mul
	xorl	%eax, %edi
	movl	-36(%ebp), %ecx
	incl	%ecx
	jmp	.L36
.L51:
	movl	%edi, %eax
	xorb	1052672(%ebx), %al
	movl	-32(%ebp), %edx
	movl	-20(%ebp), %edi
	movb	%al, (%edx,%edi)
.L35:
	decl	%esi
	addl	-28(%ebp), %ebx
	jmp	.L34
.L50:
	addl	$36, %esp
	popl	%ebx
	popl	%esi
	popl	%edi
	popl	%ebp
	ret
	.size	gauss_solve.constprop.2, .-gauss_solve.constprop.2
	.section	.text.unlikely
.LCOLDE2:
	.text
.LHOTE2:
	.section	.text.unlikely
.LCOLDB3:
	.text
.LHOTB3:
	.globl	grub_reed_solomon_recover
	.type	grub_reed_solomon_recover, @function
grub_reed_solomon_recover:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%edi
	pushl	%esi
	pushl	%ebx
	subl	$68, %esp
	movl	%eax, -56(%ebp)
	movl	%edx, -32(%ebp)
	movl	%ecx, -24(%ebp)
	testl	%ecx, %ecx
	je	.L52
	addl	%edx, %eax
	movl	%eax, -44(%ebp)
	leal	-1(%eax,%ecx), %ecx
	movl	%ecx, %eax
.L54:
	cmpl	-44(%ebp), %eax
	jb	.L55
	cmpb	$0, (%eax)
	jne	.L55
	decl	%eax
	jmp	.L54
.L55:
	subl	%eax, %ecx
	movl	$2, %ebx
	movl	-24(%ebp), %eax
	cltd
	idivl	%ebx
	cmpl	%eax, %ecx
	jg	.L52
	movb	$0, 1049088
	movb	$1, %al
	xorl	%edx, %edx
.L60:
	movb	%al, 1048576(%edx)
	movb	%al, 1048831(%edx)
	movzbl	%al, %ecx
	movb	%dl, 1049088(%ecx)
	testb	%al, %al
	jns	.L58
	leal	(%ecx,%ecx), %eax
	xorl	$29, %eax
	jmp	.L59
.L58:
	sall	%eax
.L59:
	incl	%edx
	cmpl	$255, %edx
	jne	.L60
.L61:
	cmpl	$0, -32(%ebp)
	je	.L52
	movl	-32(%ebp), %ecx
	addl	-24(%ebp), %ecx
	cmpl	$102400, %ecx
	jbe	.L91
	imull	$200, -32(%ebp), %eax
	xorl	%edx, %edx
	divl	%ecx
	sall	$9, %eax
	movl	%eax, -28(%ebp)
	imull	$200, -24(%ebp), %eax
	xorl	%edx, %edx
	divl	%ecx
	sall	$9, %eax
	movl	%eax, -48(%ebp)
	jmp	.L62
.L91:
	movl	-24(%ebp), %eax
	movl	%eax, -48(%ebp)
	movl	-32(%ebp), %eax
	movl	%eax, -28(%ebp)
.L62:
	movl	-28(%ebp), %eax
	addl	$511, %eax
	movl	%eax, -60(%ebp)
	movl	-56(%ebp), %eax
	movl	%eax, -52(%ebp)
	movl	-28(%ebp), %eax
	decl	%eax
	movl	%eax, -72(%ebp)
	movl	-60(%ebp), %eax
	movl	%eax, -40(%ebp)
	movl	-48(%ebp), %eax
	subl	-28(%ebp), %eax
	movl	%eax, -76(%ebp)
.L65:
	movl	-76(%ebp), %ebx
	addl	-40(%ebp), %ebx
	movl	%ebx, %eax
	shrl	$9, %eax
	movl	%eax, -16(%ebp)
	movl	-40(%ebp), %eax
	shrl	$9, %eax
	movl	%eax, -36(%ebp)
	je	.L63
	xorl	%eax, %eax
	cmpl	$0, -16(%ebp)
	jne	.L64
.L63:
	decl	-40(%ebp)
	incl	-52(%ebp)
	movl	-40(%ebp), %eax
	cmpl	-72(%ebp), %eax
	jne	.L65
	movl	-28(%ebp), %edi
	addl	%edi, -56(%ebp)
	movl	-48(%ebp), %esi
	addl	%esi, -44(%ebp)
	subl	%edi, -32(%ebp)
	subl	%esi, -24(%ebp)
	jmp	.L61
.L64:
	cmpl	-36(%ebp), %eax
	jge	.L101
	movl	%eax, %edx
	sall	$9, %edx
	movl	-52(%ebp), %esi
	movb	(%esi,%edx), %dl
	movb	%dl, 1052160(%eax)
	incl	%eax
	jmp	.L64
.L101:
	xorl	%eax, %eax
	movl	-60(%ebp), %edx
	subl	-40(%ebp), %edx
	addl	-44(%ebp), %edx
.L68:
	cmpl	-16(%ebp), %eax
	jge	.L102
	movl	%eax, %ecx
	sall	$9, %ecx
	movb	(%edx,%ecx), %cl
	movl	-36(%ebp), %esi
	movb	%cl, 1052160(%eax,%esi)
	incl	%eax
	jmp	.L68
.L102:
	shrl	$10, %ebx
	movl	%ebx, -20(%ebp)
	xorl	%esi, %esi
	movl	-36(%ebp), %eax
	movl	-16(%ebp), %ebx
	leal	-1(%eax,%ebx), %edi
.L70:
	movl	%esi, %ecx
	movl	%edi, %edx
	movl	$1052160, %eax
	call	pol_evaluate
	movb	%al, 1051904(%esi)
	incl	%esi
	cmpl	%esi, -16(%ebp)
	jg	.L70
	movl	-36(%ebp), %eax
	addl	-16(%ebp), %eax
	movl	%eax, -64(%ebp)
	decl	%eax
	movl	%eax, -68(%ebp)
	xorl	%eax, %eax
.L72:
	cmpb	$0, 1051904(%eax)
	jne	.L71
	incl	%eax
	cmpl	%eax, -16(%ebp)
	jg	.L72
.L71:
	cmpl	%eax, -16(%ebp)
	je	.L73
	movl	-20(%ebp), %eax
	leal	1(%eax), %esi
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	jmp	.L74
.L73:
	xorl	%eax, %eax
	jmp	.L75
.L76:
	movb	1051904(%eax,%edx), %bl
	movb	%bl, 1052672(%eax,%ecx)
	incl	%eax
	cmpl	-20(%ebp), %eax
	jle	.L76
	incl	%edx
	addl	%esi, %ecx
.L74:
	xorl	%eax, %eax
	cmpl	-20(%ebp), %edx
	jl	.L76
.L77:
	cmpl	%eax, -20(%ebp)
	jle	.L103
	movb	$0, 1050368(%eax)
	incl	%eax
	jmp	.L77
.L103:
	movl	$1050368, %ecx
	movl	-20(%ebp), %edx
	movl	%edx, %eax
	call	gauss_solve.constprop.2
	xorl	%esi, %esi
	xorl	%edi, %edi
	movl	-20(%ebp), %ebx
	decl	%ebx
.L79:
	cmpl	-64(%ebp), %esi
	jge	.L104
	movl	$255, %ecx
	subl	%esi, %ecx
	movl	%ebx, %edx
	movl	$1050368, %eax
	call	pol_evaluate
	cmpb	1048576(%esi), %al
	jne	.L80
	movl	%edi, %edx
	movb	%al, 1050624(%edi)
	incl	%edi
	movl	-68(%ebp), %eax
	subl	%esi, %eax
	movl	%eax, 1050880(,%edx,4)
.L80:
	incl	%esi
	jmp	.L79
.L104:
	xorl	%eax, %eax
.L82:
	cmpl	%eax, %edi
	je	.L105
	movb	$1, 1052672(%eax)
	incl	%eax
	jmp	.L82
.L105:
	movb	1051904, %al
	movb	%al, 1052672(%edi)
	leal	1(%edi), %eax
	movl	%eax, -64(%ebp)
	leal	(%edi,%edi), %eax
	movl	%eax, -20(%ebp)
	xorl	%ecx, %ecx
	movl	$1, %esi
.L84:
	cmpl	%esi, -16(%ebp)
	jle	.L86
	movl	-64(%ebp), %eax
	addl	%ecx, %eax
	movl	%eax, -68(%ebp)
	xorl	%ebx, %ebx
.L87:
	cmpl	%ebx, %edi
	je	.L106
	movzbl	1052672(%ebx,%ecx), %edx
	movl	%ecx, -80(%ebp)
	movzbl	1050624(%ebx), %eax
	call	gf_mul
	movl	-68(%ebp), %edx
	movb	%al, 1052672(%ebx,%edx)
	incl	%ebx
	movl	-80(%ebp), %ecx
	jmp	.L87
.L106:
	movb	1051904(%esi), %al
	movl	-20(%ebp), %ebx
	movb	%al, 1052673(%ebx)
	incl	%esi
	movl	-64(%ebp), %ebx
	addl	%ebx, -20(%ebp)
	movl	-68(%ebp), %ecx
	jmp	.L84
.L86:
	movl	$1052416, %ecx
	movl	%edi, %edx
	movl	-16(%ebp), %eax
	call	gauss_solve.constprop.2
	xorl	%eax, %eax
.L88:
	cmpl	%eax, %edi
	je	.L73
	movl	1050880(,%eax,4), %edx
	movb	1052416(%eax), %cl
	xorb	%cl, 1052160(%edx)
	incl	%eax
	jmp	.L88
.L75:
	movb	1052160(%eax), %cl
	movl	%eax, %edx
	sall	$9, %edx
	movl	-52(%ebp), %edi
	movb	%cl, (%edi,%edx)
	incl	%eax
	cmpl	%eax, -36(%ebp)
	jg	.L75
	jmp	.L63
.L52:
	addl	$68, %esp
	popl	%ebx
	popl	%esi
	popl	%edi
	popl	%ebp
	ret
	.size	grub_reed_solomon_recover, .-grub_reed_solomon_recover
	.section	.text.unlikely
.LCOLDE3:
	.text
.LHOTE3:
	.section	.note.GNU-stack,"",@progbits
