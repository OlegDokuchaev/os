#include <linux/init_task.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/sched/signal.h>  /* Для current */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OLEG DOKUCAEV");

/* Функция преобразования состояния процесса в текст */
static const char *state_to_str(long state)
{
    if (state == TASK_RUNNING)
        return "RUNNING";
    if (state & TASK_INTERRUPTIBLE)
        return "SLEEPING (interruptible)";
    if (state & TASK_UNINTERRUPTIBLE)
        return "SLEEPING (uninterruptible)";
    if (state & TASK_STOPPED)
        return "STOPPED";
    if (state & TASK_TRACED)
        return "TRACED";
    if (state & EXIT_ZOMBIE)
        return "ZOMBIE";
    if (state & EXIT_DEAD)
        return "DEAD";
    return "UNKNOWN";
}

/* Функция преобразования политики планирования в текст */
static const char *policy_to_str(int policy)
{
    switch(policy) {
        case SCHED_NORMAL: /* также SCHED_OTHER */
            return "SCHED_NORMAL (CFS) - стандартная политика с использованием Completely Fair Scheduler";
        case SCHED_FIFO:
            return "SCHED_FIFO - политика реального времени (First In, First Out)";
        case SCHED_RR:
            return "SCHED_RR - политика реального времени с циклическим распределением (Round Robin)";

        default:
            return "UNKNOWN";
    }
}

static int __init mod_init(void)
{
    printk(KERN_INFO " + module is loaded.\n");

    /* Перебор всех задач начиная с init_task */
    struct task_struct *task = &init_task;
    do {
        printk(KERN_INFO " + %s (%d) (state: %s, policy: %s, prio: %d, core_occupation: %d, exit_state: %d, exit_code: %d, exit_signal: %d), parent %s (%d)\n",
            task->comm,
            task->pid, 
            state_to_str(task->__state),
            policy_to_str(task->policy),
            task->prio, 
            task->core_occupation,
            task->exit_state,
            task->exit_code,
            task->exit_signal,
            task->parent->comm,
            task->parent->pid);
    } while ((task = next_task(task)) != &init_task);

    /* Вывод информации о текущем процессе */
    printk(KERN_INFO " + %s (%d) (state: %s, policy: %s, prio: %d, core_occupation: %d, exit_state: %d, exit_code: %d, exit_signal: %d), parent %s (%d)\n",
        current->comm, 
        current->pid, 
        state_to_str(current->__state),
        policy_to_str(current->policy),
        current->prio, 
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
