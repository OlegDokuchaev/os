#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "myseq.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OLEG DOKUCHAEV");

#define DIRNAME   "fortuneSeqDir"
#define FILENAME  "fortuneSeqFile"
#define SYMLINK   "fortuneSeqLink"
#define FILEPATH  DIRNAME "/" FILENAME
#define PID_BUF_SIZE   16

static struct proc_dir_entry *fortune_dir;
static struct proc_dir_entry *fortune_file;
static struct proc_dir_entry *fortune_link;
static pid_t stored_pid = -1;

static ssize_t fortune_write(struct file *file,
                             const char __user *ubuf,
                             size_t len, loff_t *ppos)
{
    char buf[PID_BUF_SIZE];
    long pid;
    printk(KERN_ERR "+ fortune_pid_seq: write called, len=%zu\n", len);
    if (len == 0 || len >= PID_BUF_SIZE) {
        printk(KERN_ERR "+ fortune_pid_seq: invalid write length %zu\n", len);
        return -EINVAL;
    }
    if (copy_from_user(buf, ubuf, len)) {
        printk(KERN_ERR "+ fortune_pid_seq: copy_from_user failed\n");
        return -EFAULT;
    }
    buf[len] = '\0';
    if (kstrtol(buf, 10, &pid) < 0 || pid <= 0) {
        printk(KERN_ERR "+ fortune_pid_seq: invalid pid '%s'\n", buf);
        return -EINVAL;
    }
    stored_pid = (pid_t)pid;
    printk(KERN_ERR "+ fortune_pid_seq: stored_pid set to %d\n", stored_pid);
    *ppos = len;
    return len;
}

static int fortune_show(struct seq_file *m, void *v)
{
    struct pid *pid_struct;
    struct task_struct *task;
    printk(KERN_ERR "+ fortune_pid_seq: show called\n");

    if (stored_pid <= 0) {
        printk(KERN_ERR "+ fortune_pid_seq: no PID stored\n");
        my_seq_puts(m, "No PID stored\n");
        return 0;
    }

    pid_struct = find_get_pid(stored_pid);
    task = pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        printk(KERN_ERR "+ fortune_pid_seq: pid_task returned NULL for %d\n", stored_pid);
        my_seq_printf(m, "PID %d not found\n", stored_pid);
        return 0;
    }

    printk(KERN_ERR "+ fortune_pid_seq: formatting output for PID %d\n", stored_pid);

    my_seq_printf(m, "PID: %d\n", task->pid);
    my_seq_printf(m, "COMM: %s\n", task->comm);
    my_seq_printf(m, "PPID: %d\n", task->real_parent->pid);
    my_seq_printf(m, "TGID: %d\n", task->tgid);
    my_seq_printf(m, "STATE: %ld\n", task->__state);
    my_seq_printf(m, "FLAGS: 0x%lx\n", task->flags);
    my_seq_printf(m, "PRIO: %d\n", task->prio);
    my_seq_printf(m, "NICE: %d\n", task_nice(task));
    my_seq_printf(m, "NUM_THREADS: %d\n", task->signal->nr_threads);
    my_seq_printf(m, "TOTAL_VM: %lu\n", task->mm ? task->mm->total_vm : 0UL);
    my_seq_printf(m, "START_TIME: %llu\n", task->start_time);

    return 0;
}

static ssize_t fortune_read(struct file *file, char __user *ubuf,
                            size_t count, loff_t *ppos)
{
    ssize_t ret;
    printk(KERN_ERR "+ fortune_pid_seq: read called, count=%zu, pos=%lld\n", count, *ppos);
    ret = my_seq_read(file, ubuf, count, ppos);
    printk(KERN_ERR "+ fortune_pid_seq: read returned %zd\n", ret);
    return ret;
}

static int fortune_release(struct inode *inode, struct file *file)
{
    printk(KERN_ERR "+ fortune_pid_seq: release called\n");
    return my_single_release(inode, file);
}

static int fortune_open(struct inode *inode, struct file *file)
{
    printk(KERN_ERR "+ fortune_pid_seq: open called\n");
    return my_single_open(file, fortune_show, NULL);
}

static const struct proc_ops fops = {
    .proc_open    = fortune_open,
    .proc_read    = fortune_read,
    .proc_write   = fortune_write,
    .proc_release = fortune_release,
};

static int __init fortune_init(void)
{
    printk(KERN_ERR "+ fortune_pid_seq: init start\n");

    fortune_dir = proc_mkdir(DIRNAME, NULL);
    if (!fortune_dir) {
        printk(KERN_ERR "+ fortune_pid_seq: proc_mkdir failed\n");
        return -ENOMEM;
    }
    printk(KERN_ERR "+ fortune_pid_seq: created /proc/%s\n", DIRNAME);

    fortune_file = proc_create(FILENAME, 0666, fortune_dir, &fops);
    if (!fortune_file) {
        printk(KERN_ERR "+ fortune_pid_seq: proc_create failed\n");
        remove_proc_entry(DIRNAME, NULL);
        return -ENOMEM;
    }
    printk(KERN_ERR "+ fortune_pid_seq: created /proc/%s/%s\n", DIRNAME, FILENAME);

    fortune_link = proc_symlink(SYMLINK, NULL, FILEPATH);
    if (!fortune_link) {
        printk(KERN_ERR "+ fortune_pid_seq: proc_symlink failed\n");
        remove_proc_entry(FILENAME, fortune_dir);
        remove_proc_entry(DIRNAME, NULL);
        return -ENOMEM;
    }
    printk(KERN_ERR "+ fortune_pid_seq: created /proc/%s (symlink) -> %s\n", SYMLINK, FILEPATH);

    printk(KERN_ERR "+ fortune_pid_seq: init completed\n");
    return 0;
}

static void __exit fortune_exit(void)
{
    printk(KERN_ERR "+ fortune_pid_seq: exit start\n");
    remove_proc_entry(SYMLINK, NULL);
    printk(KERN_ERR "+ fortune_pid_seq: removed symlink %s\n", SYMLINK);
    remove_proc_entry(FILENAME, fortune_dir);
    printk(KERN_ERR "+ fortune_pid_seq: removed file %s\n", FILENAME);
    remove_proc_entry(DIRNAME, NULL);
    printk(KERN_ERR "+ fortune_pid_seq: removed directory %s\n", DIRNAME);
    printk(KERN_ERR "+ fortune_pid_seq: exit completed\n");
}

module_init(fortune_init);
module_exit(fortune_exit);
