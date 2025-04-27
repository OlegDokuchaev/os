#include <linux/init.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/printk.h>
#include "myseq.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oleg Dokuchaev");

extern int my_single_open(struct file *file,
                          int (*show)(struct seq_file *, void *),
                          void *data)
{
    printk(KERN_ERR "+ myseq: my_single_open\n");
    return single_open(file, show, data);
}

extern ssize_t my_seq_read(struct file *file, char __user *buf,
                           size_t size, loff_t *ppos)
{
    ssize_t ret;
    printk(KERN_ERR "+ myseq: my_seq_read size=%zu pos=%lld\n", size, *ppos);
    ret = seq_read(file, buf, size, ppos);
    printk(KERN_ERR "+ myseq: my_seq_read -> %zd\n", ret);
    return ret;
}

extern int my_single_release(struct inode *inode, struct file *file)
{
    printk(KERN_ERR "+ myseq: my_single_release\n");
    return single_release(inode, file);
}

extern void my_seq_printf(struct seq_file *m, const char *fmt, ...)
{
    va_list args;
    printk(KERN_ERR "+ myseq: my_seq_printf\n");
    va_start(args, fmt);
    seq_vprintf(m, fmt, args);
    va_end(args);
}

extern void my_seq_puts(struct seq_file *m, const char *s)
{
    printk(KERN_ERR "+ myseq: my_seq_puts \"%s\"\n", s);
    seq_puts(m, s);
}

EXPORT_SYMBOL(my_single_open);
EXPORT_SYMBOL(my_seq_read);
EXPORT_SYMBOL(my_single_release);
EXPORT_SYMBOL(my_seq_printf);
EXPORT_SYMBOL(my_seq_puts);

static int __init myseq_init(void)
{
    printk(KERN_ERR "+ myseq: wrapper loaded\n");
    return 0;
}

static void __exit myseq_exit(void)
{
    printk(KERN_ERR "+ myseq: wrapper unloaded\n");
}

module_init(myseq_init);
module_exit(myseq_exit);
