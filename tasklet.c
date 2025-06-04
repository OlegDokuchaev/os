#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <asm/atomic.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/time.h>
#include <asm/io.h>
#include <linux/proc_fs.h>
#include <linux/jiffies.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DOKUCHAEV OLEG");

#define IRQ_NO 1
#define BUF_SIZE 128

char *ascii[] = {
        "None",
        "Esc",
        "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "=",
        "Backspace",
        "Tab",
        "Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P", "[", "]",
        "Enter",
        "Left Ctrl",
        "A", "S", "D", "F", "G", "H", "J", "K", "L", ";", "'",
        "`",
        "Left Shift",
        "\\", "Z", "X", "C", "V", "B", "N", "M", ",", ".", "/",
        "Right Shift",
        "Keypad *",
        "Left Alt",
        "Space",
        "Caps Lock",
        "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10"
};

static struct tasklet_struct *tasklet = NULL;
static char buffer[BUF_SIZE];

static int my_proc_show(struct seq_file *m, void *v) {
    seq_printf(m, "Last pressed key: %s\n", buffer);
    return 0;
}

static int my_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, my_proc_show, NULL);
}

static const struct proc_ops proc_fops = {
        .proc_open = my_proc_open,
        .proc_read = seq_read,
        .proc_release = single_release,
};

void my_tasklet_fun(unsigned long data)
{
    printk(KERN_INFO "+ tasklet: tasklet begin\n");

    int code = inb(0x60);

    if ((code >= 0x47 && code <= 0x53) || code == 0x1C)
        return;
    if (code & 0x80)
        return;

    code &= 0x7F;
    if (code >= 0 && code < sizeof(ascii) / sizeof(ascii[0])) {
        printk(KERN_INFO "+ tasklet: Key pressed: %s (code=0x%02x)\n", ascii[code], code);
        snprintf(buffer, sizeof(buffer), "%s (code=0x%02x)", ascii[code], code);
    } else {
        printk(KERN_INFO "+ tasklet: Unknown key code: 0x%02x\n", code);
        snprintf(buffer, sizeof(buffer), "Unknown (code=0x%02x)", code);
    }
}

static irqreturn_t my_irq_handler(int irq, void *dev_id)
{
    if (irq == IRQ_NO)
    {
        tasklet_schedule(tasklet);
        return IRQ_HANDLED;
    }
    return IRQ_NONE;
}

static int __init my_init(void)
{
    int ret = request_irq(IRQ_NO, my_irq_handler, IRQF_SHARED, "my_irq_handler_tasklet", (void *)(my_irq_handler));
    if (ret)
    {
        printk(KERN_ERR "+ tasklet: request_irq err\n");
        return ret;
    }

    buffer[0] = '\0';

    tasklet = kmalloc(sizeof(struct tasklet_struct), GFP_KERNEL);
    if (!tasklet)
    {
        printk(KERN_ERR "+ tasklet: kmalloc tasklet err\n");
        free_irq(IRQ_NO, (void *)(my_irq_handler));
        return -ENOMEM;
    }
    tasklet_init(tasklet, my_tasklet_fun, 0);

    proc_create("my_tasklet", 0, NULL, &proc_fops);
    printk(KERN_INFO "+ tasklet: loaded\n");

    return 0;
}

static void __exit my_exit(void)
{
    printk(KERN_INFO "+ tasklet: exit\n");

    remove_proc_entry("my_tasklet", NULL);
    tasklet_kill(tasklet);
    kfree(tasklet);
    free_irq(IRQ_NO, (void *)(my_irq_handler));

    printk(KERN_INFO "+ tasklet: unloaded\n");
}

module_init(my_init);
module_exit(my_exit);
