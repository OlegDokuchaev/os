#ifndef _MYSEQ_H
#define _MYSEQ_H

#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/printk.h>

extern int     my_single_open(struct file *file,
                       int (*show)(struct seq_file *, void *),
                       void *data);
extern ssize_t my_seq_read(struct file *file, char __user *buf,
                    size_t size, loff_t *ppos);
extern int     my_single_release(struct inode *inode, struct file *file);
extern void    my_seq_printf(struct seq_file *m, const char *fmt, ...);
extern void    my_seq_puts(struct seq_file *m, const char *s);

#endif
