#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <asm/io.h>
#include <linux/stddef.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

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

static struct proc_dir_entry *proc_file;
static struct workqueue_struct *my_wq;
static struct work_struct work;
static char buffer[BUF_SIZE] = {0};
static int current_key_code = 0;

static int my_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Last pressed key: %s\n", buffer);
    return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, my_proc_show, NULL);
}

static const struct proc_ops proc_fops = {
        .proc_open = proc_open,
        .proc_read = seq_read,
        .proc_release = single_release,
};

void my_work_func(struct work_struct *work)
{
    int code = current_key_code;
    printk(KERN_INFO "+ wq: work begin\n");

    if ((code >= 0x47 && code <= 0x53) || code == 0x1C)
        return;
    if (code & 0x80)
        return;

    code &= 0x7F;
    if (code >= 0 && code < sizeof(ascii) / sizeof(ascii[0])) {
        printk(KERN_INFO "+ wq: Key pressed: %s (code=0x%02x)\n", ascii[code], code);
        snprintf(buffer, sizeof(buffer), "%s (code=0x%02x)", ascii[code], code);
    } else {
        printk(KERN_INFO "+ wq: Unknown key code: 0x%02x", code);
        snprintf(buffer, sizeof(buffer), "Unknown (code=0x%02x)\n", code);
    }
}

irqreturn_t my_irq_handler(int irq, void *dev)
{
    int code;
    printk(KERN_INFO "+ wq: my_irq_handler\n");

    if (irq == IRQ_NO)
    {
        printk(KERN_INFO "+ wq: called by keyboard_irq\n");
        code = inb(0x60);
        printk(KERN_INFO "+ wq: key code is %d\n", code);

        current_key_code = code;
        queue_work(my_wq, &work);

        return IRQ_HANDLED;
    }

    return IRQ_NONE;
}

static int __init my_wq_init(void)
{
    printk(KERN_INFO "+ wq: init");

    proc_file = proc_create("my_wq", 0, NULL, &proc_fops);
    if (!proc_file) {
        printk(KERN_ERR "+ fortune_pid: proc_create file failed\n");
        return -ENOMEM;
    }

    int ret = request_irq(IRQ_NO, my_irq_handler, IRQF_SHARED, "my_irq_handler_wq", (void *)my_irq_handler);
    if (ret) {
        printk(KERN_ERR "+ wq: request_irq error\n");
        remove_proc_entry("my_wq", NULL);
        return ret;
    }

    my_wq = alloc_workqueue("my_wq", __WQ_LEGACY | WQ_MEM_RECLAIM, 1);
    if (!my_wq) {
        printk(KERN_ERR "+ wq: create queue error\n");
        remove_proc_entry("my_wq", NULL);
        free_irq(IRQ_NO, (void *)my_irq_handler);
        return -ENOMEM;
    }
    INIT_WORK(&work, my_work_func);

    printk(KERN_INFO "+ wq: loaded\n");
    return 0;
}

static void __exit my_wq_exit(void)
{
    printk(KERN_INFO "+ wq: exit\n");

    synchronize_irq(IRQ_NO);
    free_irq(IRQ_NO, (void *)my_irq_handler);
    remove_proc_entry("my_wq", NULL);
    flush_workqueue(my_wq);
    destroy_workqueue(my_wq);

    printk(KERN_INFO "+ wq: unloaded\n");
}

module_init(my_wq_init);
module_exit(my_wq_exit);
