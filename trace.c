#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/compat.h>

#ifdef CONFIG_X86_32
# define IS_IA32		1
#elif defined(CONFIG_IA32_EMULATION)
# define IS_IA32		is_compat_task()
#else
# define IS_IA32		0
#endif

#ifndef __NR_ia32_open
# define __NR_ia32_open		__NR_open
#endif

static void trace_syscall_entry(int arch, unsigned long major, \
	unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3)
{
	char *filename = NULL;

	if (major == __NR_open || major == __NR_ia32_open) {
		filename = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!filename || strncpy_from_user(filename, (const void __user *)a0, PATH_MAX) < 0)
			goto out;
		printk("%s open(%s) [%s]\n", arch ? "X86_64" : "I386", filename, current->comm);
	}

out:
	if (filename) kfree(filename);
}

void ServiceTraceEnter(struct pt_regs *regs)
{
	if (IS_IA32)
		trace_syscall_entry(0, regs->orig_ax, \
			regs->bx, regs->cx, regs->dx, regs->si);
#ifdef CONFIG_X86_64
	else
		trace_syscall_entry(1, regs->orig_ax, \
			regs->di, regs->si, regs->dx, regs->r10);

#endif
}

static void trace_syscall_leave(struct pt_regs *regs)
{
	/* TODO: add more code here */
}

void ServiceTraceLeave(struct pt_regs *regs)
{
	trace_syscall_leave(regs);
}
