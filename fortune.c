/*  fortune_pid.c ─ пример без goto с логированием всех действий через printk(KERN_ERR) и описанным выводом /proc/<pid>/stat  */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maslova Marina (PID‑версия, логгирование через printk)");

#define DIRNAME   "fortuneDir"
#define FILENAME  "fortuneFile"
#define SYMLINK   "fortuneLink"
#define FILEPATH  DIRNAME "/" FILENAME

#define PID_BUF_SIZE   16
#define STAT_BUF_SIZE  (PAGE_SIZE * 2)
#define OUT_BUF_SIZE   (STAT_BUF_SIZE * 2)

static struct proc_dir_entry *fortune_dir;
static struct proc_dir_entry *fortune_file;
static struct proc_dir_entry *fortune_link;

static char    *stat_buf;
static ssize_t  stat_len;
static pid_t    stored_pid = -1;

static const char *task_descr =
    "(1) pid            '%d'
"
    "(2) comm           '%s'
"
    "(3) state          '%ld'
"
    "(4) ppid           '%d'
"
    "(5) tgid           '%d'
"
    "(6) session        '%d'
"
    "(7) flags          '0x%lx'
"
    "(8) priority       '%d'
"
    "(9) nice           '%d'
"
    "(10) num_threads   '%d'
"
    "(11) mm->total_vm  '%lu'
"
    "(12) start_time    '%llu'
";

static int fortune_open(struct inode *inode, struct file *file)
{
    printk(KERN_ERR "+ fortune_pid: open called\n");
    return 0;
}

static int fortune_release(struct inode *inode, struct file *file)
{
    printk(KERN_ERR "+ fortune_pid: release called\n");
    return 0;
}

static ssize_t fortune_write(struct file *file,
                             const char __user *ubuf,
                             size_t len, loff_t *ppos)
{
    char pid_buf[PID_BUF_SIZE];
    long pid;
    int ret;

    printk(KERN_ERR "+ fortune_pid: write called, len=%zu\n", len);
    if (len == 0 || len >= PID_BUF_SIZE) {
        printk(KERN_ERR "+ fortune_pid: write invalid length %zu\n", len);
        return -EINVAL;
    }
    if (copy_from_user(pid_buf, ubuf, len)) {
        printk(KERN_ERR "+ fortune_pid: write copy_from_user failed\n");
        return -EFAULT;
    }
    pid_buf[len] = '\0';

    ret = kstrtol(pid_buf, 10, &pid);
    if (ret < 0 || pid <= 0) {
        printk(KERN_ERR "+ fortune_pid: write invalid pid '%s'\n", pid_buf);
        return -EINVAL;
    }

    stored_pid = (pid_t)pid;
    stat_len = 0;
    printk(KERN_ERR "+ fortune_pid: stored_pid set to %d\n", stored_pid);
    return len;
}

static ssize_t fortune_read(struct file *file,
                            char __user *ubuf,
                            size_t count, loff_t *ppos)
{
    struct pid *pid_struct;
    struct task_struct *task;
    char *out_buf;
    ssize_t out_len;
    int ret;

    printk(KERN_ERR "+ fortune_pid: read called, count=%zu, pos=%lld\n", count, *ppos);
    if (*ppos > 0)
        return 0;
    if (stored_pid <= 0) {
        printk(KERN_ERR "+ fortune_pid: no PID stored\n");
        return -EINVAL;
    }

    pid_struct = find_get_pid(stored_pid);
    if (!pid_struct) {
        printk(KERN_ERR "+ fortune_pid: find_get_pid failed for %d\n", stored_pid);
        return -ESRCH;
    }

    task = pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        printk(KERN_ERR "+ fortune_pid: pid_task returned NULL for %d\n", stored_pid);
        return -ESRCH;
    }

    /* Выделяем буфер для вывода */
    out_buf = kmalloc(OUT_BUF_SIZE, GFP_KERNEL);
    if (!out_buf) {
        printk(KERN_ERR "+ fortune_pid: kmalloc out_buf failed\n");
        return -ENOMEM;
    }

    /* Формируем вывод */
    rcu_read_lock();
    out_len = scnprintf(out_buf, OUT_BUF_SIZE,
        task_descr,
        task->pid,
        task->comm,
        task->state,
        task->real_parent->pid,
        task->tgid,
        task->signal->session->leader->pid,
        task->flags,
        task->prio,
        task_nice(task),
        task->signal->nr_threads,
        task->mm ? task->mm->total_vm : 0UL,
        task->start_time);
    rcu_read_unlock();

    if (out_len > count)
        out_len = count;
    ret = copy_to_user(ubuf, out_buf, out_len);
    kfree(out_buf);
    if (ret) {
        printk(KERN_ERR "+ fortune_pid: copy_to_user failed\n");
        return -EFAULT;
    }

    *ppos = out_len;
    printk(KERN_ERR "+ fortune_pid: read returning %zd bytes\n", out_len);
    return out_len;
}

static const struct proc_ops fops = {
    .proc_open    = fortune_open,
    .proc_read    = fortune_read,
    .proc_write   = fortune_write,
    .proc_release = fortune_release,
};

static int __init fortune_init(void)
{
    printk(KERN_ERR "+ fortune_pid: init start\n");

    stat_buf = vmalloc(STAT_BUF_SIZE);
    if (!stat_buf) {
        printk(KERN_ERR "+ fortune_pid: vmalloc stat_buf failed\n");
        return -ENOMEM;
    }
    printk(KERN_ERR "+ fortune_pid: allocated stat_buf\n");

    fortune_dir = proc_mkdir(DIRNAME, NULL);
    if (!fortune_dir) {
        printk(KERN_ERR "+ fortune_pid: proc_mkdir failed\n");
        vfree(stat_buf);
        return -ENOMEM;
    }
    printk(KERN_ERR "+ fortune_pid: created /proc/%s directory\n", DIRNAME);

    fortune_file = proc_create(FILENAME, 0666, fortune_dir, &fops);
    if (!fortune_file) {
        printk(KERN_ERR "+ fortune_pid: proc_create file failed\n");
        remove_proc_entry(DIRNAME, NULL);
        vfree(stat_buf);
        return -ENOMEM;
    }
    printk(KERN_ERR "+ fortune_pid: created /proc/%s/%s file\n", DIRNAME, FILENAME);

    fortune_link = proc_symlink(SYMLINK, NULL, FILEPATH);
    if (!fortune_link) {
        printk(KERN_ERR "+ fortune_pid: proc_symlink failed\n");
        remove_proc_entry(FILENAME, fortune_dir);
        remove_proc_entry(DIRNAME, NULL);
        vfree(stat_buf);
        return -ENOMEM;
    }
    printk(KERN_ERR "+ fortune_pid: created /proc/%s symlink to %s\n", SYMLINK, FILEPATH);

    printk(KERN_ERR "+ fortune_pid: init completed\n");
    return 0;
}

static void __exit fortune_exit(void)
{
    printk(KERN_ERR "+ fortune_pid: exit start\n");
    remove_proc_entry(SYMLINK, NULL);
    printk(KERN_ERR "+ fortune_pid: removed symlink %s\n", SYMLINK);
    remove_proc_entry(FILENAME, fortune_dir);
    printk(KERN_ERR "+ fortune_pid: removed file %s\n", FILENAME);
    remove_proc_entry(DIRNAME, NULL);
    printk(KERN_ERR "+ fortune_pid: removed directory %s\n", DIRNAME);
    vfree(stat_buf);
    printk(KERN_ERR "+ fortune_pid: freed stat_buf and exit completed\n");
}

module_init(fortune_init);
module_exit(fortune_exit);
