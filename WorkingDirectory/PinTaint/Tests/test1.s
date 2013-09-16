	.file	"test1.c"
	.text
	.globl	foo
	.type	foo, @function
foo:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -24(%rbp)
	movq	-24(%rbp), %rax
	movzbl	(%rax), %eax
	movb	%al, -1(%rbp)
	movq	-24(%rbp), %rax
	movzbl	4(%rax), %eax
	movb	%al, -1(%rbp)
	movq	-24(%rbp), %rax
	movzbl	8(%rax), %eax
	movb	%al, -1(%rbp)
	movq	-24(%rbp), %rax
	movzbl	10(%rax), %eax
	movb	%al, -1(%rbp)
	movq	-24(%rbp), %rax
	addq	$5, %rax
	movb	$116, (%rax)
	movq	-24(%rbp), %rax
	addq	$10, %rax
	movb	$101, (%rax)
	movq	-24(%rbp), %rax
	addq	$20, %rax
	movb	$115, (%rax)
	movq	-24(%rbp), %rax
	addq	$30, %rax
	movb	$116, (%rax)
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	foo, .-foo
	.section	.rodata
.LC0:
	.string	"./file.txt"
	.text
	.globl	main
	.type	main, @function
main:
.LFB1:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movl	%edi, -20(%rbp)
	movq	%rsi, -32(%rbp)
	movl	$256, %edi
	call	malloc
	movq	%rax, -8(%rbp)
	cmpq	$0, -8(%rbp)
	jne	.L3
	movl	$-1, %eax
	jmp	.L2
.L3:
	movl	$0, %esi
	movl	$.LC0, %edi
	movl	$0, %eax
	call	open
	movl	%eax, -12(%rbp)
	movq	-8(%rbp), %rcx
	movl	-12(%rbp), %eax
	movl	$256, %edx
	movq	%rcx, %rsi
	movl	%eax, %edi
	movl	$0, %eax
	call	read
	movl	-12(%rbp), %eax
	movl	%eax, %edi
	movl	$0, %eax
	call	close
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	foo
.L2:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	main, .-main
	.ident	"GCC: (GNU) 4.8.1 20130725 (prerelease)"
	.section	.note.GNU-stack,"",@progbits
