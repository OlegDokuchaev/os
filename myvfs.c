#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/mnt_idmapping.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/list.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DOKUCHAEV OLEG");

#define MYVFS_MAGIC_NUMBER 0x13131313
#define SLAB_NAME "myvfs Slab Cache"
#define OBJECTS_PER_MOUNT 1

static struct kmem_cache *cache = NULL;
static atomic_t mount_count = ATOMIC_INIT(0);

struct my_fs_inode {
    int i_mode;
    unsigned long i_ino;
};

struct cache_entry {
    struct my_fs_inode *inode;
    struct list_head list;
};

struct my_fs_mount_data {
    struct list_head entries;
    int num_objects;
};

static struct inode *my_fs_make_inode(struct super_block *sb, int mode)
{
    struct inode *ret = new_inode(sb);
    struct mnt_idmap *idmap = &nop_mnt_idmap;

    if (ret) {
        inode_init_owner(idmap, ret, NULL, mode);
        ret->i_size = PAGE_SIZE;
        ret->i_atime_sec = ret->i_mtime_sec = ret->i_ctime_sec = current_time(ret).tv_sec;
        ret->i_ino = 1;
    }

    printk(KERN_INFO "myvfs: MY_FS_MAKE_INODE (struct inode created)\n");
    return ret;
}

static void my_fs_put_super(struct super_block *sb)
{
    printk(KERN_INFO "myvfs: MY_FS_PUT_SUPER (super block destroyed)!\n");
}

static int my_fs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    printk(KERN_INFO "myvfs: statfs called\n");
    return simple_statfs(dentry, buf);
}

static int my_fs_delete_inode(struct inode *inode)
{
    printk(KERN_INFO "myvfs: delete_inode called\n");
    return generic_delete_inode(inode);
}
//!!!
static struct super_operations const my_fs_sup_ops = {
        .put_super = my_fs_put_super,
        .statfs = my_fs_statfs,
        .drop_inode = my_fs_delete_inode
};

static void my_ctor(void *p)
{
    struct my_fs_inode *inode = (struct my_fs_inode *)p;
    memset(inode, 0, sizeof(struct my_fs_inode));
    inode->i_mode = 0;
    inode->i_ino = 0;
}

static int my_fs_fill_sb(struct super_block *sb, void *data, int silent)
{
    struct inode *root_inode;
    sb->s_blocksize = PAGE_SIZE;
    sb->s_blocksize_bits = PAGE_SHIFT;
    sb->s_magic = MYVFS_MAGIC_NUMBER;
    sb->s_op = &my_fs_sup_ops;

    root_inode = my_fs_make_inode(sb, S_IFDIR | 0755);
    if (!root_inode) {
        printk(KERN_ERR "myvfs: my_fs_make_inode error\n");
        return -ENOMEM;
    }

    root_inode->i_atime_sec = root_inode->i_mtime_sec = root_inode->i_ctime_sec = current_time(root_inode).tv_sec;
    root_inode->i_op = &simple_dir_inode_operations;
    root_inode->i_fop = &simple_dir_operations;

    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root) {
        printk(KERN_ERR "myvfs: d_make_root error\n");
        iput(root_inode);
        return -ENOMEM;
    }

    printk(KERN_INFO "myvfs: VFS root created\n");
    return 0;
}

static struct dentry *my_fs_mount(struct file_system_type *type, int flags,
                                  const char *dev, void *data)
{
    struct dentry *const root = mount_nodev(type, flags, data, my_fs_fill_sb);
    int current_mounts;
    int i;
    struct my_fs_mount_data *mount_data;

    if (IS_ERR(root)) {
        printk(KERN_ERR "myvfs: mounting failed\n");
        return root;
    }

    mount_data = kzalloc(sizeof(struct my_fs_mount_data), GFP_KERNEL);
    if (!mount_data) {
        printk(KERN_ERR "myvfs: failed to allocate mount data\n");
        return ERR_PTR(-ENOMEM);
    }

    INIT_LIST_HEAD(&mount_data->entries);
    mount_data->num_objects = 0;
    current_mounts = atomic_inc_return(&mount_count);

    for (i = 0; i < OBJECTS_PER_MOUNT; i++) {
        struct cache_entry *entry = kmalloc(sizeof(struct cache_entry), GFP_KERNEL);
        if (!entry) {
            printk(KERN_ERR "myvfs: kmalloc for cache_entry failed\n");
            continue;
        }
        entry->inode = kmem_cache_alloc(cache, GFP_KERNEL);
        if (!entry->inode) {
            printk(KERN_ERR "myvfs: slab alloc failed\n");
            kfree(entry);
            continue;
        }
        entry->inode->i_mode = S_IFREG | 0644;
        entry->inode->i_ino = i + 1;
        list_add(&entry->list, &mount_data->entries);
        mount_data->num_objects++;
    }

    root->d_sb->s_fs_info = mount_data;

    printk(KERN_ERR "myvfs: MY_FS_MOUNT (mount count: %d, objects: %d)\n",
            current_mounts, mount_data->num_objects);
    return root;
}

static void my_kill_litter_super(struct super_block *sb)
{
    struct my_fs_mount_data *mount_data = sb->s_fs_info;
    struct cache_entry *entry, *tmp;
    int current_mounts;
    if (!mount_data) {
        printk(KERN_ERR "myvfs: No mount data found\n");
        kill_litter_super(sb);
        return;
    }

    printk(KERN_ERR "myvfs: KILL_LITTER_SUPER, freeing %d inodes\n", mount_data->num_objects);

    list_for_each_entry_safe(entry, tmp, &mount_data->entries, list) {
        list_del(&entry->list);
        //printk(KERN_INFO "myvfs: Freeing object, inode %p\n", entry->inode);
        kmem_cache_free(cache, entry->inode);
        kfree(entry);
    }
    kfree(mount_data);
    sb->s_fs_info = NULL;

    current_mounts = atomic_dec_return(&mount_count);
    printk(KERN_INFO "myvfs: MY_KILL_LITTER_SUPER (mount count: %d)\n", current_mounts);

    kill_litter_super(sb);
}

static struct file_system_type my_fs_type = {
        .owner   = THIS_MODULE,
        .name    = "myvfs",
        .mount   = my_fs_mount,
        .kill_sb = my_kill_litter_super
};

static int __init my_fs_init(void)
{
    int ret;

    struct padded_inode {
        struct my_fs_inode inode;
        char padding[PAGE_SIZE - sizeof(struct my_fs_inode) - 1];
    };

    cache = kmem_cache_create(SLAB_NAME, sizeof(struct padded_inode), 0,
                              SLAB_HWCACHE_ALIGN, my_ctor);
    if (!cache) {
        printk(KERN_ERR "myvfs: kmem_cache_create error\n");
        return -ENOMEM;
    }

    ret = register_filesystem(&my_fs_type);
    if (ret != 0) {
        printk(KERN_ERR "myvfs: register_filesystem error\n");
        kmem_cache_destroy(cache);
        return ret;
    }

    printk(KERN_ERR "myvfs: INIT\n");
    return 0;
}

static void __exit my_fs_exit(void)
{
    if (unregister_filesystem(&my_fs_type) != 0)
        printk(KERN_ERR "myvfs: unregister_filesystem error\n");

    if (cache) {
        kmem_cache_destroy(cache);
        cache = NULL;
    }

    printk(KERN_ERR "myvfs: EXIT\n");
}

module_init(my_fs_init);
module_exit(my_fs_exit);
