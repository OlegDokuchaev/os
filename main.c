#include <linux/init_task.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OLEG DOKUCAEV");

static int __init mod_init(void)
{
    printk(KERN_INFO " + module is loaded.\n");
    struct task_struct *task = &init_task;
    do
    {
        printk(KERN_INFO " + %s (%d) (%d - state, %d - prio, policy - %d, core_occupation - %d, exit_state - %d, exit_code - %d, exit_signal - %d), parent %s (%d)",
            task->comm,
            task->pid, 
            task->__state, 
            task->prio, 
            task->policy,
            task->core_occupation,
            task->exit_state,
            task->exit_code,
            task->exit_signal,
            task->parent->comm,
            task->parent->pid);
    } while ((task = next_task(task)) != &init_task);

    printk(KERN_INFO " + %s (%d) (%d - state, %d - prio, policy - %d, core_occupation - %d, exit_state - %d, exit_code - %d, exit_signal - %d), parent %s (%d)",
        current->comm, 
        current->pid, 
        current->__state, 
        current->prio, 
        current->policy,
        current->core_occupation,
        current->exit_state,
        current->exit_code,
        current->exit_signal,
        current->parent->comm,
        current->parent->pid);
    return 0;
}

static void __exit mod_exit(void)
{
    printk(KERN_INFO " + %s - %d, parent %s - %d\n",
           current->comm,
           current->pid, 
           current->parent->comm, 
           current->parent->pid);
    printk(KERN_INFO " + module is unloaded.\n");
}

module_init(mod_init);
module_exit(mod_exit);
