#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/kallsyms.h>
#include <linux/stop_machine.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include "udis86.h"

#define debug(fmt...)				\
	pr_info("[" KBUILD_MODNAME "] " fmt)

#define to_ptr(x)				\
	(void *)((unsigned long)(x))

typedef typeof(module_alloc) modalloc_t;
modalloc_t *modalloc = NULL;

//
// x86 helpers
//

typedef struct {
	unsigned short limit;
	void * base;
} __attribute__((packed)) x86_idt_reg_t;

typedef struct {
	unsigned short offset_low;
	unsigned short selector;
	unsigned char zero1;
	unsigned char type;
#ifdef CONFIG_X86_64
	unsigned short offset_middle;
	unsigned int offset_high;
	unsigned int zero2;
#else
	unsigned short offset_high;
#endif
} __attribute__((packed)) x86_idt_desc_t;

static unsigned long long x86_get_msr(int msr)
{
	unsigned long msrl = 0, msrh = 0;

	/* NOTE: rdmsr is always return EDX:EAX pair value */
	asm volatile ("rdmsr" : "=a"(msrl), "=d"(msrh) : "c"(msr));

	return ((unsigned long long)msrh << 32) | msrl;
}

static void *x86_get_isr(int vec)
{
	x86_idt_reg_t reg;
	x86_idt_desc_t desc;
	unsigned long address;

	asm volatile("sidt %0" : "=m"(reg));

	memcpy(&desc, reg.base + vec * sizeof(desc), sizeof(desc));

	address = desc.offset_high;
#ifdef CONFIG_X86_64
	address = (address << 16) | desc.offset_middle;
#endif
	address = (address << 16) | desc.offset_low;

	return to_ptr(address);
}

static void x86_insert_jmp(void *a, const void *f, const void *t)
{
	*((char *)(a + 0)) = 0xE9;
	*(( int *)(a + 1)) = (long)(t - (f + 5));
}

static void x86_insert_call(void *a, const void *f, const void *t, int insn_len)
{
	/* 5-byte CALL REL32 -- E8 xx.xx.xx.xx */
	if (insn_len == 5) {
		*((char *)(a + 0)) = 0xE8;
		*(( int *)(a + 1)) = (long)(t - (f + 5));
	}

	/* 7-byte CALL MEM32 -- FF.14.x5 xx.xx.xx.xx */
	if (insn_len == 7) {
		*((char *)(a + 0)) = 0xFF;
		*((char *)(a + 1)) = 0x14;
#ifdef CONFIG_X86_64
		*((char *)(a + 2)) = 0xC5;
#else
		*((char *)(a + 2)) = 0x85;
#endif
		*(( int *)(a + 3)) = (long)t;
	}
}

//
// kernel symbol lookup helper
//

typedef struct {
	const char * name;
	void * address;
} ksymstr_t;

static int on_each_symbol(void *data, const char *name, struct module *module, unsigned long address)
{
	ksymstr_t *sym = to_ptr(data);

	if (strcmp(name, sym->name) == 0) {
		sym->address = to_ptr(address);
		return 1;
	}

	return 0;
}

void *get_symbol_address(const char *name)
{
	ksymstr_t sym = {
		.name = name, .address = NULL,
	};

	kallsyms_on_each_symbol(on_each_symbol, &sym);

	return sym.address;
}

//
// udis86 helpers
//

const void *ud_find_insn(const void *entry, int limit, enum ud_mnemonic_code insn_mne, int insn_len)
{
	ud_t ud;
	const void *result = NULL;

	ud_initialize(&ud, BITS_PER_LONG, UD_VENDOR_ANY, entry, limit);
	while (ud_disassemble(&ud)) {
		if (ud.mnemonic == insn_mne && ud_insn_len(&ud) == insn_len) {
			result = entry + ud_insn_off(&ud);
			break;
		}
	}

	return result;
}

//
// system call entry hooking
//

#define STUB_SIZE	512

static uint8_t *stubsarea = NULL;

typedef struct scentry {

	const char	*name;

	const void	*entry;
	const void	*table;

	const void	*pcall;
	void		*pcall_map;

	void		*stub;
	const void	*handler;

	void		(*prepare)(struct scentry *);
	void		(*implant)(struct scentry *);
	void		(*restore)(struct scentry *);
	void		(*cleanup)(struct scentry *);

} scentry_t;

/*
 * map_writable creates a shadow page mapping of the range
 * [addr, addr + len) so that we can write to code mapped read-only.
 *
 * It is similar to a generalized version of x86's text_poke.  But
 * because one cannot use vmalloc/vfree() inside stop_machine, we use
 * map_writable to map the pages before stop_machine, then use the
 * mapping inside stop_machine, and unmap the pages afterwards.
 *
 * STOLEN from: https://github.com/jirislaby/ksplice
 */

static void *map_writable(const void *addr, size_t len)
{
	void *vaddr;
	int nr_pages = DIV_ROUND_UP(offset_in_page(addr) + len, PAGE_SIZE);
	struct page **pages = kmalloc(nr_pages * sizeof(*pages), GFP_KERNEL);
	void *page_addr = (void *)((unsigned long)addr & PAGE_MASK);
	int i;

	if (pages == NULL)
		return NULL;

	for (i = 0; i < nr_pages; i++) {
		if (__module_address((unsigned long)page_addr) == NULL) {
			pages[i] = virt_to_page(page_addr);
			WARN_ON(!PageReserved(pages[i]));
		} else {
			pages[i] = vmalloc_to_page(page_addr);
		}
		if (pages[i] == NULL) {
			kfree(pages);
			return NULL;
		}
		page_addr += PAGE_SIZE;
	}
	vaddr = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
	kfree(pages);
	if (vaddr == NULL)
		return NULL;
	return vaddr + offset_in_page(addr);
}

static void fixup_stub(scentry_t *se)
{
	ud_t ud;

	memset(se->stub, 0x90, STUB_SIZE);

	ud_initialize(&ud, BITS_PER_LONG, \
		UD_VENDOR_ANY, se->handler, STUB_SIZE);

	while (ud_disassemble(&ud)) {
		void *insn = se->stub + ud_insn_off(&ud);
		const void *orig_insn = se->handler + ud_insn_off(&ud);

		memcpy(insn, orig_insn, ud_insn_len(&ud));

		/* fixup sys_call_table dispatcher calls (FF.14.x5.xx.xx.xx.xx) */
		if (ud.mnemonic == UD_Icall && ud_insn_len(&ud) == 7) {
			x86_insert_call(insn, NULL, se->table, 7);
			continue;
		}

		/* fixup ServiceTraceEnter/Leave calls (E8.xx.xx.xx.xx) */
		if (ud.mnemonic == UD_Icall && ud_insn_len(&ud) == 5) {
			x86_insert_call(insn, insn, orig_insn + (long)(*(int *)(orig_insn + 1)) + 5, 5);
			continue;
		}

		/* fixup jump back (E9.xx.xx.xx.xx) */
		if (ud.mnemonic == UD_Ijmp && ud_insn_len(&ud) == 5) {
			x86_insert_jmp(insn, insn, se->pcall + 7);
			break;
		}
	}

	se->pcall_map = map_writable(se->pcall, 64);
}

#if defined (CONFIG_X86_64)
#if defined (CONFIG_IA32_EMULATION)
extern void service_syscall32(void);
static void prepare_syscall32(scentry_t *se)
{
	/*
	 * searching for -- 'call *ia32_sys_call_table(,%rax,8)'
	 *     http://lxr.free-electrons.com/source/arch/x86/ia32/ia32entry.S?v=3.13#L320
	 */

	se->entry = get_symbol_address(se->name);
	se->entry = se->entry ? se->entry : to_ptr(x86_get_msr(MSR_CSTAR));
	if (!se->entry) return;

	se->pcall = ud_find_insn(se->entry, 512, UD_Icall, 7);
	if (!se->pcall) return;

	se->table = to_ptr(*(int *)(se->pcall + 3));
}
#endif
extern void service_syscall64(void);
static void prepare_syscall64_1(scentry_t *se)
{
	/*
	 * searching for -- 'call *sys_call_table(,%rax,8)'
	 *     http://lxr.free-electrons.com/source/arch/x86/kernel/entry_64.S?v=3.13#L629
	 */

	se->entry = get_symbol_address(se->name);
	se->entry = se->entry ? se->entry : to_ptr(x86_get_msr(MSR_LSTAR));
	if (!se->entry) return;

	se->pcall = ud_find_insn(se->entry, 512, UD_Icall, 7);
	if (!se->pcall) return;

	se->table = to_ptr(*(int *)(se->pcall + 3));
}
extern void service_syscall64(void);
static void prepare_syscall64_2(scentry_t *se)
{
	const void *jtracesys;

	/*
	 * searching for -- 'jnz tracesys' (1 step)
	 *     http://lxr.free-electrons.com/source/arch/x86/kernel/entry_64.S?v=3.13#L619
	 */

	se->entry = get_symbol_address(se->name);
	se->entry = se->entry ? se->entry : to_ptr(x86_get_msr(MSR_LSTAR));
	if (!se->entry) return;

	jtracesys = ud_find_insn(se->entry, 512, UD_Ijnz, 6);
	if (!jtracesys) return;

	/*
	 * searching for -- 'call *sys_call_table(,%rax,8)' (2 step)
	 *     http://lxr.free-electrons.com/source/arch/x86/kernel/entry_64.S?v=3.13#L629
	 */

	se->pcall = ud_find_insn(jtracesys + *(int *)(jtracesys + 2), 512, UD_Icall, 7);
	if (!se->pcall) return;

	se->table = to_ptr(*(int *)(se->pcall + 3));
}
#endif

#if defined (CONFIG_X86_32) || defined (CONFIG_IA32_EMULATION)
extern void service_int80(void);
static void prepare_int80(scentry_t *se)
{
	/*
	 * searching for -- 'call *ia32_sys_call_table(,%rax,4)' (x86_32)
	 *      http://lxr.free-electrons.com/source/arch/x86/kernel/entry_32.S?v=3.13#L515
	 * searching for -- 'call *ia32_sys_call_table(,%rax,8)' (x86_64 + ia32e)
	 *      http://lxr.free-electrons.com/source/arch/x86/ia32/ia32entry.S?v=3.13#L428
	 */

	se->entry = get_symbol_address(se->name);
	se->entry = se->entry ? se->entry : to_ptr(x86_get_isr(0x80));
	if (!se->entry) return;

	se->pcall = ud_find_insn(se->entry, 512, UD_Icall, 7);
	if (!se->pcall) return;

	se->table = to_ptr(*(int *)(se->pcall + 3));
}
extern void service_sysenter(void);
static void prepare_sysenter(scentry_t *se)
{
	/*
	 * searching for -- 'call *ia32_sys_call_table(,%rax,4)' (x86_32)
	 *      http://lxr.free-electrons.com/source/arch/x86/kernel/entry_32.S?v=3.13#L435
	 * searching for -- 'call *ia32_sys_call_table(,%rax,8)' (x86_64 + ia32e)
	 *      http://lxr.free-electrons.com/source/arch/x86/ia32/ia32entry.S?v=3.13#L163
	 */

	se->entry = get_symbol_address(se->name);
	se->entry = se->entry ? se->entry : to_ptr(x86_get_msr(MSR_IA32_SYSENTER_EIP));
	if (!se->entry) return;

	se->pcall = ud_find_insn(se->entry, 512, UD_Icall, 7);
	if (!se->pcall) return;

	se->table = to_ptr(*(int *)(se->pcall + 3));
}
#endif

/* called under the stop_machine() */
static void generic_implant(scentry_t *se)
{
	if (!se->pcall_map) return;

	debug("  [o] implanting jump to stub handler %p (%s)\n", se->stub, se->name);

	x86_insert_jmp(se->pcall_map, se->pcall, se->stub);
}

/* called under the stop_machine() */
static void generic_restore(scentry_t *se)
{
	ud_t ud;

	if (!se->pcall_map) return;

	ud_initialize(&ud, BITS_PER_LONG, \
		UD_VENDOR_ANY, se->stub, STUB_SIZE);

	while (ud_disassemble(&ud)) {
		if (ud.mnemonic == UD_Icall && ud_insn_len(&ud) == 5) {
			memset(se->stub + ud_insn_off(&ud), 0x90, ud_insn_len(&ud));
			continue;
		}
		if (ud.mnemonic == UD_Ijmp)
			break;
	}

	debug("  [o] restoring original call instruction %p (%s)\n", se->pcall, se->name);

	x86_insert_call(se->pcall_map, NULL, se->table, 7);
}

static void generic_cleanup(scentry_t *se)
{
	if (!se->pcall_map) return;

	vunmap(to_ptr((unsigned long)se->pcall_map & PAGE_MASK));

	debug("  [o] cleanning up resources (%s)\n", se->name);
}

/*
 * List of all the possible entries
 */

scentry_t elist[] = {
#ifdef CONFIG_X86_64
#ifdef CONFIG_IA32_EMULATION
	{
		.name = "ia32_syscall",				/* INT 0x80: IDT(0x80), ia32/ia32entry.S (emu) */
		.handler = service_int80,
		.prepare = prepare_int80,
	},
	{
		.name = "ia32_sysenter_target",			/* SYSENTER: MSR(IA32_SYSENTER_EIP), ia32/ia32entry.S (emu) */
		.handler = service_sysenter,
		.prepare = prepare_sysenter,
	},
	{
		.name = "ia32_cstar_target",			/* SYSCALL32: MSR(CSTAR), ia32/ia32entry.S (emu) */
		.handler = service_syscall32,
		.prepare = prepare_syscall32,
	},
#endif
	{
		.name = "system_call",				/* SYSCALL: MSR(LSTAR), kernel/entry_64.S (1) */
		.handler = service_syscall64,
		.prepare = prepare_syscall64_1
	},
	{
		.name = "system_call",				/* SYSCALL: MSR(LSTAR), kernel/entry_64.S (2) */
		.handler = service_syscall64,
		.prepare = prepare_syscall64_2
	},
#else
	{
		.name = "system_call",				/* INT 0x80: IDT(0x80), kernel/entry_32.S */
		.handler = service_int80,
		.prepare = prepare_int80,
	},
	{
		.name = "ia32_sysenter_target",
		.handler = service_sysenter,
		.prepare = prepare_sysenter,			/* SYSENTER: MSR(IA32_SYSENTER_TARGET), kernel/entry_32.S */
	},
#endif
};

static int prepare(void)
{
	int i;

	debug("# prepare\n");

	for (i = 0; i < ARRAY_SIZE(elist); i++) {
		scentry_t *se = &elist[i];

		se->stub = stubsarea + STUB_SIZE * i;

		if (!se->implant) se->implant = generic_implant;
		if (!se->restore) se->restore = generic_restore;
		if (!se->cleanup) se->cleanup = generic_cleanup;

		se->prepare(&elist[i]);
		if (se->table) fixup_stub(se);

		debug("  [o] prepared stub %p (%s)\n", se->stub, se->name);
		debug("      entry:%p pcall:%p table:%p\n", se->entry, se->pcall, se->table);
	}

	debug("# prepare OK\n");

	return 0;
}

static int do_implant(void *arg)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(elist); i++)
		elist[i].implant(&elist[i]);

	return 0;
}

static int implant(void)
{
	int result;

	debug("# implant\n");
	result = stop_machine(do_implant, NULL, NULL);
	debug("# implant OK\n");

	return result;
}

static int do_restore(void *arg)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(elist); i++)
		elist[i].restore(&elist[i]);

	return 0;
}

static void restore(void)
{
	debug("# restore\n");
	stop_machine(do_restore, NULL, NULL);
	debug("# restore OK\n");
}

static void cleanup(void)
{
	int i;

	debug("# cleanup\n");

	for (i = 0; i < ARRAY_SIZE(elist); i++)
		elist[i].cleanup(&elist[i]);

	debug("# cleanup OK\n");
}

int init_module(void)
{
	debug("# SYSCALL hooking module\n");

	modalloc = (modalloc_t *)get_symbol_address("module_alloc");
	if (!modalloc)
		return -EINVAL;

	stubsarea = modalloc(STUB_SIZE * ARRAY_SIZE(elist));
	if (!stubsarea)
		return -ENOMEM;

	return (prepare() || implant());
}

void cleanup_module(void)
{
	restore();
	cleanup();

	debug("# DONE\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ilya V. Matveychikov <i.matveychikov@securitycode.ru>");
