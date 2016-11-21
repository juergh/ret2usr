/*
 * Copyright 2016, Hewlett Packard Enterprise Development, L.P.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include <asm/pgtable.h>

#include "ret2usr.h"

#define __VERIFY_READ (1 << 0)
#define __VERIFY_EXEC (1 << 1)

char DATA_BUF[] = "!!! code from userspace !!!";

static int ret2usr_major;
static struct class *ret2usr_class;
static struct mm_struct *__init_mm;

/*
 * Copy of lookup_address_in_pgd() from arch/x86/mm/pageattr.c
 */
static pte_t *__lookup_addr_in_pgd(pgd_t *pgd, unsigned long addr,
				   unsigned int *level)
{
	pud_t *pud;
	pmd_t *pmd;

        *level = PG_LEVEL_NONE;

        if (pgd_none(*pgd))
                return NULL;

	pud = pud_offset(pgd, addr);
	if (pud_none(*pud))
		return NULL;

        *level = PG_LEVEL_1G;
	if (pud_large(*pud) || !pud_present(*pud))
		return (pte_t *)pud;

        pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;

        *level = PG_LEVEL_2M;
	if (pmd_large(*pmd) || !pmd_present(*pmd))
		return (pte_t *)pmd;

	*level = PG_LEVEL_4K;

        return pte_offset_kernel(pmd, addr);
}

/*
 * Look up a virtual (process or kernel) address and return its PTE
 *
 * Based on lookup_address() from arch/x86/mm/pageattr.c
 */
static pte_t *__lookup_addr(unsigned long addr, unsigned int *level)
{
	pgd_t *pgd;

	if (addr > PAGE_OFFSET) {
		/* kernel virtual address */
		pgd = pgd_offset(__init_mm, addr);
	} else {
		/* user (process) virtual address */
		pgd = pgd_offset(current->mm, addr);
	}

	return __lookup_addr_in_pgd(pgd, addr, level);
}

/*
 * Convert a user (process) virtual address to a physical address
 *
 * Based on slow_virt_to_phys() from arch/x86/mm/pageattr.c
 */
static unsigned long user_to_phys(unsigned long user_addr)
{
	unsigned long phys_addr;
        unsigned long offset;
        unsigned int level;
	pte_t *pte;

	printk("ret2usr: pid: %d, comm: %s\n", current->pid, current->comm);

	pte = __lookup_addr(user_addr, &level);
	if (!pte)
		return 0;

	/*
	 * pXX_pfn() returns unsigned long, which must be cast to phys_addr_t
	 * before being left-shifted PAGE_SHIFT bits -- this trick is to
	 * make 32-PAE kernel work correctly.
	 */
	switch (level) {
	case PG_LEVEL_1G:
		phys_addr = (unsigned long)pud_pfn(*(pud_t *)pte) << PAGE_SHIFT;
		offset = user_addr & ~PUD_PAGE_MASK;
		break;
	case PG_LEVEL_2M:
		phys_addr = (unsigned long)pmd_pfn(*(pmd_t *)pte) << PAGE_SHIFT;
		offset = user_addr & ~PMD_PAGE_MASK;
		break;
	default:
		phys_addr = (unsigned long)pte_pfn(*pte) << PAGE_SHIFT;
		offset = user_addr & ~PAGE_MASK;
	}

	return (unsigned long)(phys_addr | offset);
}

/*
 * Convert a physical address to a kernel virtual address
 */
static unsigned long phys_to_kern(unsigned long phys_addr)
{
	return (unsigned long)phys_to_virt(phys_addr);
}

/*
 * Verify if a virtual address is readable and/or executable
 */
static int verify_addr(unsigned long addr, int flags)
{
	unsigned long unused;
	unsigned int level;
	pte_t *pte;

	if (flags & __VERIFY_READ) {
		if (probe_kernel_read(&unused, (void *)addr, sizeof(unused))) {
			printk("ret2usr: addr: %p, unable to probe\n",
			       (void *)addr);
			return -EFAULT;
		}
	}

	if (flags & __VERIFY_EXEC) {
		pte = __lookup_addr(addr, &level);
		if (!pte) {
			printk("ret2usr: addr: %p, bad pte\n", (void *)addr);
			return -EFAULT;
		}

		if (!pte_present(*pte)) {
			printk("ret2user: addr: %p, pte not present\n",
			       (void *)addr);
			return -EFAULT;
		}

		if (!pte_exec(*pte)) {
			printk("ret2usr: addr: %p, page is no-execute (NX) "
			       "protected\n", (void *)addr);
			return -EACCES;
		}
	}

	return 0;
#if 0
	if ((pgd_flags(*pgd) & _PAGE_USER) &&(__read_cr4() & X86_CR4_SMEP)) {
		printk("ret2usr: addr: %p, unable to execute userspace code\n",
		       addr);
		return -EPERM;
	}
#endif
}

static int ret2usr_open(struct inode *i, struct file *f)
{
	printk("ret2usr: device opened\n");
	return 0;
}

static int ret2usr_release(struct inode *i, struct file *f)
{
	printk("ret2usr: device released\n");
	return 0;
}


static long ret2usr_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct ret2usr_req *req = (struct ret2usr_req *)arg;
	void (*__memcpy)(void *dst, const void *src, size_t len);

	printk("ret2usr: ioctl_cmd: %x\n", cmd);
	printk("ret2usr: user_addr: %p\n", (void *)req->user_addr);

	switch(cmd) {

	case RET2USR_READ:
		req->status = verify_addr(req->user_addr, __VERIFY_READ);
		if (!req->status) {
			printk("ret2usr: reading %d bytes from user_addr %p\n",
			       req->len, (void *)req->user_addr);
			memcpy((void *)req->data, (void *)req->user_addr,
			       req->len);
		}
		break;

	case RET2DIR_READ:
		req->phys_addr = user_to_phys(req->user_addr);
		req->kern_addr = phys_to_kern(req->phys_addr);

		req->status = verify_addr(req->kern_addr, __VERIFY_READ);
		if (!req->status) {
			printk("ret2usr: reading %d bytes from kern_addr %p\n",
			       req->len, (void *)req->kern_addr);
			memcpy((void *)req->data, (void *)req->kern_addr,
			       req->len);
		}
		break;

	case RET2USR_EXEC:
		req->status = verify_addr(req->user_addr, __VERIFY_EXEC);
		if (!req->status) {
			printk("ret2usr: executing code from user_addr %p\n",
			       (void *)req->user_addr);
			__memcpy = (void *)req->user_addr;
			__memcpy((void *)req->data, (void *)DATA_BUF,
				sizeof(DATA_BUF));
		}
		break;

	case RET2DIR_EXEC:
		req->phys_addr = user_to_phys(req->user_addr);
		req->kern_addr = phys_to_kern(req->phys_addr);

		req->status = verify_addr(req->kern_addr, __VERIFY_EXEC);
		if (!req->status) {
			printk("ret2usr: executing code from kern_addr %p\n",
			       (void *)req->kern_addr);
			__memcpy = (void *)req->kern_addr;
			__memcpy((void *)req->data, (void *)DATA_BUF,
				 sizeof(DATA_BUF));
		}
		break;

	default:
		req->status = -EINVAL;
		printk("ret2usr: unknown ioctl cmd\n");
		break;
	}

	return 0;
}

static struct file_operations ret2usr_fops = {
	.open = ret2usr_open,
	.release = ret2usr_release,
	.unlocked_ioctl = ret2usr_ioctl,
};

static int __init ret2usr_init(void)
{
	int err;

	__init_mm = (struct mm_struct *)kallsyms_lookup_name("init_mm");
	if (!__init_mm) {
		printk("ret2usr: failed to lookup 'init_mm'\n");
		err = -ENXIO;
		goto out;
	}
	printk("ret2usr: init_mm: %p\n", __init_mm);

	ret2usr_major = register_chrdev(0, "ret2usr", &ret2usr_fops);
	if (ret2usr_major < 0) {
		printk("ret2usr: failed to register device\n");
		err = ret2usr_major;
		goto out;
	}

	ret2usr_class = class_create(THIS_MODULE, "ret2usr");
	if (IS_ERR(ret2usr_class)) {
		printk("ret2usr: failed to create class\n");
		err = PTR_ERR(ret2usr_class);
		goto out_unregister;
	}

	device_create(ret2usr_class, NULL, MKDEV(ret2usr_major, 0), NULL,
		      "ret2usr");

	printk("ret2usr: module loaded\n");
	return 0;

out_unregister:
	unregister_chrdev(ret2usr_major, "ret2usr");
out:
	return err;
}

static void __exit ret2usr_exit(void)
{
	device_destroy(ret2usr_class, MKDEV(ret2usr_major, 0));
	class_destroy(ret2usr_class);
	unregister_chrdev(ret2usr_major, "ret2usr");

	printk("ret2usr: module unloaded\n");
}

module_init(ret2usr_init);
module_exit(ret2usr_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Juerg Haefliger <juerg.haefliger@hpe.com>");
MODULE_DESCRIPTION("Module to exploit ret2usr (and ret2dir) attacks");
