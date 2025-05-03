#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>

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

static ssize_t my__read(struct file *file, char __user *buf,
                           size_t count, loff_t *ppos)
{
    ssize_t ret;
    printk(KERN_ERR "+ myseq: my_read called, count=%zu, pos=%lld\n", count, *ppos);
    ret = seq_read(file, buf, count, ppos);
    return ret;
}

static int my__release(struct inode *inode, struct file *file)
{
    int ret;
    printk(KERN_ERR "+ myseq: my_release called\n");
    ret = single_release(inode, file);
    return ret;
}

static ssize_t my__write(struct file *file,
                             const char __user *ubuf,
                             size_t len, loff_t *ppos)
{
    char buf[PID_BUF_SIZE];
    long pid;
    printk(KERN_ERR "+ myseq: write called, len=%zu\n", len);
    if (len == 0 || len >= PID_BUF_SIZE) {
        return -EINVAL;
    }
    if (copy_from_user(buf, ubuf, len)) {
        return -EFAULT;
    }
    buf[len] = '\0';
    if (kstrtol(buf, 10, &pid) < 0 || pid <= 0) {
        return -EINVAL;
    }
    stored_pid = (pid_t)pid;
    *ppos = len;
    return len;
}

static int my__show(struct seq_file *m, void *v)
{
    struct pid *pid_struct;
    struct task_struct *task;
    printk(KERN_ERR "+ myseq: show called\n");

    if (stored_pid <= 0) {
        return 0;
    }

    pid_struct = find_get_pid(stored_pid);
    task = pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        return 0;
    }

    seq_printf(m, "PID: %d\n", task->pid);
    seq_printf(m, "COMM: %s\n", task->comm);
    seq_printf(m, "PPID: %d\n", task->real_parent->pid);
    seq_printf(m, "TGID: %d\n", task->tgid);
    seq_printf(m, "STATE: %l=d\n", task->__state);
    seq_printf(m, "FLAGS: 0x%x\n", task->flags);
    seq_printf(m, "PRIO: %d\n", task->prio);
    seq_printf(m, "NICE: %d\n", task_nice(task));
    seq_printf(m, "NUM_THREADS: %d\n", task->signal->nr_threads);
    seq_printf(m, "TOTAL_VM: %lu\n", task->mm ? task->mm->total_vm : 0UL);
    seq_printf(m, "START_TIME: %llu\n", task->start_time);

    return 0;
}

static int my__open(struct inode *inode, struct file *file)
{
    printk(KERN_ERR "+ myseq: single_open\n");
    return single_open(file, my__show, NULL);
}

static const struct proc_ops fops = {
    .proc_open    = my__open,
    .proc_read    = my__read,
    .proc_write   = my__write,
    .proc_release = my__release
};

static int __init fortune_init(void)
{
    printk(KERN_ERR "+ fortune_pid_seq: init start\n");

    fortune_dir = proc_mkdir(DIRNAME, NULL);
    if (!fortune_dir) {
        return -ENOMEM;
    }

    fortune_file = proc_create(FILENAME, 0666, fortune_dir, &fops);
    if (!fortune_file) {
        remove_proc_entry(DIRNAME, NULL);
        return -ENOMEM;
    }

    fortune_link = proc_symlink(SYMLINK, NULL, FILEPATH);
    if (!fortune_link) {
        remove_proc_entry(FILENAME, fortune_dir);
        remove_proc_entry(DIRNAME, NULL);
        return -ENOMEM;
    }

    return 0;
}

static void __exit fortune_exit(void)
{
    printk(KERN_ERR "+ fortune_pid_seq: exit start\n");
    remove_proc_entry(SYMLINK, NULL);
    remove_proc_entry(FILENAME, fortune_dir);
    remove_proc_entry(DIRNAME, NULL);
}

module_init(fortune_init);
module_exit(fortune_exit);
