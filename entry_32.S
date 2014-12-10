#undef CONFIG_AS_CFI
#include <asm/dwarf2.h>
#include <asm/calling.h>
#include <asm/asm-offsets.h>
#include <linux/linkage.h>

.global service_int80
service_int80:
	movl	%esp, %eax
	call	ServiceTraceEnter

	movl	PT_ORIG_EAX(%esp), %eax
	call	*0x00000000(,%eax,4)		// origin call
	movl	%eax, PT_EAX(%esp)

	movl	%esp, %eax
	call	ServiceTraceLeave

	mov	PT_EAX(%esp), %eax
	jmp	0x00000000

.global service_sysenter
service_sysenter:
	movl	%esp, %eax
	call	ServiceTraceEnter

	movl	PT_ORIG_EAX(%esp), %eax
	call	*0x00000000(,%eax,4)		// origin call
	movl	%eax, PT_EAX(%esp)

	movl	%esp, %eax
	call	ServiceTraceLeave

	mov	PT_EAX(%esp), %eax
	jmp	0x00000000
