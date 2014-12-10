#undef CONFIG_AS_CFI
#include <asm/dwarf2.h>
#include <asm/calling.h>
#include <asm/asm-offsets.h>
#include <linux/linkage.h>

#ifdef CONFIG_IA32_EMULATION

.macro IA32_ARG_FIXUP noebp=0
	movl	%edi, %r8d
	.if \noebp
	.else
	movl	%ebp, %r9d
	.endif
	xchg	%ecx, %esi
	movl	%ebx, %edi
	movl	%edx, %edx	/* zero extension */
.endm

.macro LOAD_ARGS32 offset, _r9=0
	.if \_r9
	movl	\offset + 16(%rsp), %r9d
	.endif
	movl	\offset + 40(%rsp), %ecx
	movl	\offset + 48(%rsp), %edx
	movl	\offset + 56(%rsp), %esi
	movl	\offset + 64(%rsp), %edi
	movl	%eax, %eax	/* zero extension */
.endm

.global service_int80
service_int80:
	SAVE_REST
	movq	%rsp, %rdi
	call	ServiceTraceEnter
	RESTORE_REST

	LOAD_ARGS32 0
	IA32_ARG_FIXUP
	movq	ORIG_RAX - ARGOFFSET(%rsp), %rax
	call	*0x00000000(,%rax,8)			// origin call
	movq	%rax, RAX - ARGOFFSET(%rsp)

	SAVE_REST
	movq	%rsp, %rdi
	call	ServiceTraceLeave
	RESTORE_REST

	movq	RAX - ARGOFFSET(%rsp), %rax
	jmp	0x00000000

.global service_sysenter
service_sysenter:
	SAVE_REST
	movq	%rsp, %rdi
	call	ServiceTraceEnter
	RESTORE_REST

	LOAD_ARGS32 0
	IA32_ARG_FIXUP
	movq	ORIG_RAX - ARGOFFSET(%rsp), %rax
	call	*0x00000000(,%rax,8)			// origin call
	movq	%rax, RAX - ARGOFFSET(%rsp)

	SAVE_REST
	movq	%rsp, %rdi
	call	ServiceTraceLeave
	RESTORE_REST

	movq	RAX - ARGOFFSET(%rsp), %rax
	jmp	0x00000000

.global service_syscall32
service_syscall32:
	SAVE_REST
	movq	%rsp, %rdi
	call	ServiceTraceEnter
	RESTORE_REST

	LOAD_ARGS32 0
	IA32_ARG_FIXUP 1
	movq	ORIG_RAX - ARGOFFSET(%rsp), %rax
	call	*0x00000000(,%rax,8)			// origin call
	movq	%rax, RAX - ARGOFFSET(%rsp)

	SAVE_REST
	movq	%rsp, %rdi
	call	ServiceTraceLeave
	RESTORE_REST

	movq	RAX - ARGOFFSET(%rsp), %rax
	jmp	0x00000000

#endif /* CONFIG_IA32_EMULATION */

.global service_syscall64
service_syscall64:
	SAVE_REST
	movq	%rsp, %rdi
	call	ServiceTraceEnter
	RESTORE_REST

	LOAD_ARGS 0
	movq	%r10, %rcx
	movq	ORIG_RAX - ARGOFFSET(%rsp), %rax
	call	*0x00000000(,%rax,8)			// origin call
	movq	%rax, RAX - ARGOFFSET(%rsp)

	SAVE_REST
	movq	%rsp, %rdi
	call	ServiceTraceLeave
	RESTORE_REST

	movq	RAX - ARGOFFSET(%rsp), %rax
	jmp	0x00000000
