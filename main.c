#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OLEG DOKUCHAEV");

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

static const char *stat_no_descr[] = {
    "(1) pid           '%s'\n",
    "(2) comm          '%s'\n",
    "(3) state         '%s'\n",
    "(4) ppid          '%s'\n",
    "(5) pgrp          '%s'\n",
    "(6) session       '%s'\n",
    "(7) tty_nr        '%s'\n",
    "(8) tpgid         '%s'\n",
    "(9) flags         '%s'\n",
    "(10) minflt       '%s'\n",
    "(11) cminflt      '%s'\n",
    "(12) majflt       '%s'\n",
    "(13) cmajflt      '%s'\n",
    "(14) utime        '%s'\n",
    "(15) stime        '%s'\n",
    "(16) cutime       '%s'\n",
    "(17) cstime       '%s'\n",
    "(18) priority     '%s'\n",
    "(19) nice         '%s'\n",
    "(20) num_threads  '%s'\n",
    "(21) itrealvalue  '%s'\n",
    "(22) starttime    '%s'\n",
    "(23) vsize        '%s'\n",
    "(24) rss          '%s'\n",
    "(25) rsslim       '%s'\n",
    "(26) startcode    '%s'\n",
    "(27) endcode      '%s'\n",
    "(28) startstack   '%s'\n",
    "(29) kstkesp      '%s'\n",
    "(30) kstkeip      '%s'\n",
    "(31) signal       '%s'\n",
    "(32) blocked      '%s'\n",
    "(33) sigignore    '%s'\n",
    "(34) sigcatch     '%s'\n",
    "(35) wchan        '%s'\n",
    "(36) nswap        '%s'\n",
    "(37) cnswap       '%s'\n",
    "(38) exit_signal  '%s'\n",
    "(39) processor    '%s'\n",
    "(40) rt_priority  '%s'\n",
    "(41) policy       '%s'\n",
    "(42) delayacct_blkio_ticks '%s'\n",
    "(43) guest_time   '%s'\n",
    "(44) cguest_time  '%s'\n",
    "(45) start_data   '%s'\n",
    "(46) end_data     '%s'\n",
    "(47) start_brk    '%s'\n",
    "(48) arg_start    '%s'\n",
    "(49) arg_end      '%s'\n",
    "(50) env_start    '%s'\n",
    "(51) env_end      '%s'\n",
    "(52) exit_code    '%s'\n"
};

static ssize_t fetch_stat(pid_t pid)
{
    char path[32];
    struct file *filp;
    loff_t pos = 0;
    ssize_t n;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp))
        return PTR_ERR(filp);

    n = kernel_read(filp, stat_buf, STAT_BUF_SIZE - 1, &pos);
    filp_close(filp, NULL);

    if (n > 0)
        stat_buf[n] = '\0';
    return n;
}

static int fortune_open(struct inode *inode, struct file *file)
{
    pr_info("fortune_pid: open\n");
    return 0;
}

static int fortune_release(struct inode *inode, struct file *file)
{
    pr_info("fortune_pid: release\n");
    return 0;
}

static ssize_t fortune_write(struct file *file,
                             const char __user *ubuf,
                             size_t len, loff_t *ppos)
{
    char pid_buf[PID_BUF_SIZE];
    long pid;
    int ret;

    pr_info("fortune_pid: write (%zu bytes)\n", len);
    if (len == 0 || len >= PID_BUF_SIZE)
        return -EINVAL;
    if (copy_from_user(pid_buf, ubuf, len))
        return -EFAULT;
    pid_buf[len] = '\0';

    ret = kstrtol(pid_buf, 10, &pid);
    if (ret < 0 || pid <= 0)
        return -EINVAL;

    stored_pid = (pid_t)pid;
    stat_len = 0;
    return len;
}

static ssize_t fortune_read(struct file *file,
                            char __user *ubuf,
                            size_t count, loff_t *ppos)
{
    char **fields;
    char *p, *tmp;
    ssize_t fetched, out_len = 0;
    char *out_buf;
    int i;

    if (*ppos > 0)
        return 0;
    if (stored_pid <= 0)
        return -EINVAL;

    if (stat_len == 0) {
        fetched = fetch_stat(stored_pid);
        if (fetched < 0)
            return fetched;
        stat_len = fetched;
    }

    tmp = kstrdup(stat_buf, GFP_KERNEL);
    if (!tmp)
        return -ENOMEM;

    fields = kmalloc_array(52, sizeof(char *), GFP_KERNEL);
    if (!fields) {
        kfree(tmp);
        return -ENOMEM;
    }

    p = tmp;
    for (i = 0; i < 52; i++) {
        if (!p) break;
        fields[i] = strsep(&p, " ");
    }
    kfree(tmp);

    out_buf = vmalloc(OUT_BUF_SIZE);
    if (!out_buf) {
        kfree(fields);
        return -ENOMEM;
    }
    for (i = 0; i < 52; i++) {
        out_len += scnprintf(out_buf + out_len,
                             OUT_BUF_SIZE - out_len,
                             stat_no_descr[i],
                             fields[i] ? fields[i] : "");
    }
    kfree(fields);

    if (out_len > count)
        out_len = count;
    if (copy_to_user(ubuf, out_buf, out_len))
        out_len = -EFAULT;

    *ppos = out_len;
    vfree(out_buf);
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
    pr_info("fortune_pid: init\n");

    stat_buf = vmalloc(STAT_BUF_SIZE);
    if (!stat_buf)
        return -ENOMEM;

    fortune_dir = proc_mkdir(DIRNAME, NULL);
    if (!fortune_dir) {
        vfree(stat_buf);
        return -ENOMEM;
    }

    fortune_file = proc_create(FILENAME, 0666, fortune_dir, &fops);
    if (!fortune_file) {
        remove_proc_entry(DIRNAME, NULL);
        vfree(stat_buf);
        return -ENOMEM;
    }

    fortune_link = proc_symlink(SYMLINK, NULL, FILEPATH);
    if (!fortune_link) {
        remove_proc_entry(FILENAME, fortune_dir);
        remove_proc_entry(DIRNAME, NULL);
        vfree(stat_buf);
        return -ENOMEM;
    }

    return 0;
}

static void __exit fortune_exit(void)
{
    pr_info("fortune_pid: exit\n");
    remove_proc_entry(SYMLINK, NULL);
    remove_proc_entry(FILENAME, fortune_dir);
    remove_proc_entry(DIRNAME, NULL);
    vfree(stat_buf);
}

module_init(fortune_init);
module_exit(fortune_exit);
