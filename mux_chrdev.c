/*  
 *  mux_chrdev - character device multiplexor
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/sysfs.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/mutex.h>
#include <linux/device.h>
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Scott Wagner");
MODULE_DESCRIPTION("Mux Character Device Module");

#define N_DEVICES 2
//#define MUX_CHRDEV_DEBUG

static const char * const device_name = "mux_chrdev";	/* Dev name as it appears in /proc/devices   */
static const char * const class_name = "m_chrdev";	/* Class name */
static short target_major = 0;  /* Major device number of the target device */
static short target_minor = 0;  /* Minor device number of the target device */
static short timeout = 500;  /* Device lock timeout - mS (0 => no timeout) */
module_param(target_major, short,  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
MODULE_PARM_DESC(target_major, "Major device number of the target device");
module_param(target_minor, short,  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
MODULE_PARM_DESC(target_minor, "Minor device number of the target device");
module_param(timeout, short,  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
MODULE_PARM_DESC(timeout, "Device lock timeout - mS (0 => no timeout)");

struct muxdev_data {
    dev_t mux_dev;
    int count;
    struct cdev *pcdev[N_DEVICES];
    struct device *muxdev_device[N_DEVICES];
    dev_t active_device; /* Device which currently has control, or 0 if free */
    struct class *pclass;
    int rdlen;
    dev_t backing_dev;
    wait_queue_head_t mq;
    struct timer_list timer;
    struct mutex mx;
	struct inode inode;
    struct file file;
};
static struct muxdev_data *gptd;

static int open_backing_dev(struct muxdev_data *ptd) {
    int rc;
    memset(&ptd->inode, 0, sizeof(struct inode));
    memset(&ptd->file, 0, sizeof(struct file));
    spin_lock_init(&ptd->inode.i_lock);
    spin_lock_init(&ptd->file.f_lock);
    mutex_init(&ptd->file.f_pos_lock);
    atomic_set(&ptd->file.f_count, 0);
    INIT_LIST_HEAD(&ptd->inode.i_devices);
    ptd->file.f_inode = &ptd->inode;
    init_special_inode(&ptd->inode, S_IFCHR, ptd->backing_dev);
	if ((rc = (*ptd->inode.i_fop->open)(&ptd->inode, &ptd->file)) != 0) {
        printk("Backing device open failed: %d\n", rc);
        memset(&ptd->file, 0, sizeof(struct file));
    }
    return rc;
}

static loff_t device_llseek(struct file *filp, loff_t offset, int whence)
{
    struct muxdev_data *ptd = (struct muxdev_data *)filp->private_data;
    loff_t rc;
    if (ptd->file.f_op == NULL) {
        return -ENXIO;
    } else if (ptd->file.f_op->llseek == NULL) {
        return -EINVAL;
    }
    #ifdef MUX_CHRDEV_DEBUG
	printk(KERN_INFO "%s device_llseek()\n", device_name);
    #endif
    
    rc = (*ptd->file.f_op->llseek)(&ptd->file, offset, whence);    
    
	return rc;
}

static ssize_t device_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
    struct muxdev_data *ptd = (struct muxdev_data *)filp->private_data;
    ssize_t rc;
    if (ptd->file.f_op == NULL) {
        return -ENXIO;
    } else if (ptd->file.f_op->read == NULL) {
        return -EINVAL;
    }
    mutex_lock(&ptd->mx);
    if (ptd->active_device != filp->f_inode->i_rdev) {
        if (ptd->active_device != 0) {
            #ifdef MUX_CHRDEV_DEBUG
            printk(KERN_INFO "%s device_read() minor %d blocks : user %d:%d\n", device_name,
                    MINOR(filp->f_inode->i_rdev), MAJOR(ptd->active_device), MINOR(ptd->active_device));
            #endif
            if (filp->f_flags & O_NONBLOCK) {
                mutex_unlock(&ptd->mx);
                return -EAGAIN;
            } else {
                mutex_unlock(&ptd->mx);
                if (wait_event_interruptible(ptd->mq, (ptd->active_device == 0)) != 0) {
                    return -ERESTARTSYS;
                }
                mutex_lock(&ptd->mx);
           }
        }
        #ifdef MUX_CHRDEV_DEBUG
 	    printk(KERN_INFO "%s device_read() minor %d takes lock\n", device_name, MINOR(filp->f_inode->i_rdev));
        #endif
        mod_timer(&ptd->timer, jiffies + timeout*HZ/1000);
        ptd->active_device = filp->f_inode->i_rdev;
    }
    mutex_unlock(&ptd->mx);
    rc = (*ptd->file.f_op->read)(&ptd->file, buf, len, off);
    mutex_lock(&ptd->mx);
    del_timer(&ptd->timer);
    ptd->active_device = 0;
    mutex_unlock(&ptd->mx);
    wake_up_interruptible(&ptd->mq);
    #ifdef MUX_CHRDEV_DEBUG
 	printk(KERN_INFO "%s device_read() minor %d rc %d\n", device_name, MINOR(filp->f_inode->i_rdev), (int)rc);
    #endif
    return rc;
}

static ssize_t device_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
    struct muxdev_data *ptd = (struct muxdev_data *)filp->private_data;
    ssize_t rc;
    if (ptd->file.f_op == NULL) {
        return -ENXIO;
    } else if (ptd->file.f_op->write == NULL) {
        return -EINVAL;
    }
    mutex_lock(&ptd->mx);
    if (ptd->active_device != filp->f_inode->i_rdev) {
        if (ptd->active_device != 0) {
            #ifdef MUX_CHRDEV_DEBUG
            printk(KERN_INFO "%s device_write() minor %d blocks : user %d:%d\n", device_name,
                MINOR(filp->f_inode->i_rdev), MAJOR(ptd->active_device), MINOR(ptd->active_device));
            #endif
            if (filp->f_flags & O_NONBLOCK) {
                mutex_unlock(&ptd->mx);
                return -EAGAIN;
            } else {
                mutex_unlock(&ptd->mx);
                if (wait_event_interruptible(ptd->mq, (ptd->active_device == 0)) != 0) {
                    return -ERESTARTSYS;
                }
                mutex_lock(&ptd->mx);
           }
        }
        #ifdef MUX_CHRDEV_DEBUG
 	    printk(KERN_INFO "%s device_write() minor %d takes lock\n", device_name, MINOR(filp->f_inode->i_rdev));
        #endif
        mod_timer(&ptd->timer, jiffies + timeout*HZ/1000);
        ptd->active_device = filp->f_inode->i_rdev;
    }
    mutex_unlock(&ptd->mx);
    rc = (*ptd->file.f_op->write)(&ptd->file, buf, len, off);
    #ifdef MUX_CHRDEV_DEBUG
 	printk(KERN_INFO "%s device_write() minor %d len %d\n", device_name, MINOR(filp->f_inode->i_rdev), (int)len);
    #endif
	return rc;
}

static int device_open(struct inode *inode, struct file *filp)
{
    int rc;
    struct muxdev_data *ptd = gptd;
    if (target_major == 0) {
        printk("Target device %d:%d invalid - set with \"target_major=<n>\" in module params\n"
                "or \"echo <n> > /sys/class/m_chrdev/mux_chrdev_0/major\".\n",
                MAJOR(ptd->backing_dev), MINOR(ptd->backing_dev));
        return -EINVAL;
    }
    mutex_lock(&ptd->mx);
    filp->private_data = ptd;
    if (ptd->backing_dev == 0) {
        ptd->backing_dev = MKDEV(target_major, target_minor);
        if ((rc = open_backing_dev(ptd)) != 0) {
            printk("Open of backing device %d:%d failed: %d\n",
                    MAJOR(ptd->backing_dev), MINOR(ptd->backing_dev), rc);
            ptd->backing_dev = 0;
            mutex_unlock(&ptd->mx);
            return rc;
        }
    }
    ++ptd->count;
    mutex_unlock(&ptd->mx);
    #ifdef MUX_CHRDEV_DEBUG
 	printk(KERN_INFO "%s device_open() device %d:%d, backing device %d:%d\n",
            device_name, MAJOR(filp->f_inode->i_rdev), MINOR(filp->f_inode->i_rdev),
            MAJOR(ptd->backing_dev), MINOR(ptd->backing_dev));
    #endif
	return 0;
}

static int device_release(struct inode *inode, struct file *filp)
{
    struct muxdev_data *ptd = (struct muxdev_data *)filp->private_data;
    int rc;
    mutex_lock(&ptd->mx);
    if (--ptd->count <= 0) {
        del_timer(&ptd->timer);
        ptd->backing_dev = 0;
    }
    mutex_unlock(&ptd->mx);
    if (ptd->file.f_op == NULL) {
        return -ENXIO;
    } else if (ptd->file.f_op->release == NULL) {
        return -EINVAL;
    }
    #ifdef MUX_CHRDEV_DEBUG
	printk(KERN_INFO "%s device_release()\n", device_name);
    #endif
	rc = (*ptd->file.f_op->release)(&ptd->inode, &ptd->file);
    if (ptd->backing_dev == 0) {
        memset(&ptd->inode, 0, sizeof(struct inode));
        memset(&ptd->file, 0, sizeof(struct file));
    }
    return rc;
}

static long device_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct muxdev_data *ptd = (struct muxdev_data *)filp->private_data;
     if (ptd->file.f_op == NULL) {
        return -ENXIO;
    } else if (ptd->file.f_op->unlocked_ioctl == NULL) {
        return -EINVAL;
    }
    #ifdef MUX_CHRDEV_DEBUG
	printk(KERN_INFO "%s device_ioctl()\n", device_name);
    #endif
	return (*ptd->file.f_op->unlocked_ioctl)(&ptd->file, cmd, arg);
}

#ifdef CONFIG_COMPAT
static long device_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct muxdev_data *ptd = (struct muxdev_data *)filp->private_data;
    if (ptd->file.f_op == NULL) {
        return -ENXIO;
    } else if (ptd->file.f_op->compat_ioctl == NULL) {
        return -EINVAL;
    }
    #ifdef MUX_CHRDEV_DEBUG
	printk(KERN_INFO "%s compat_ioctl()\n", device_name);
    #endif
	return (*ptd->file.f_op->compat_ioctl)(&ptd->file, cmd, arg);
}
#else
    #define device_compat_ioctl NULL
#endif

static unsigned int device_poll(struct file *filp, poll_table *wait)
{
    struct muxdev_data *ptd = (struct muxdev_data *)filp->private_data;
    unsigned int mask = 0;
    // If we own the lock right now, poll looks at the backing device poll
    if (ptd->active_device == filp->f_inode->i_rdev ||
            ptd->active_device == 0) {
        if (ptd->file.f_op == NULL) {
            return -ENXIO;
        } else if (ptd->file.f_op->poll == NULL) {
            mask = POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM;
        } else {
            /* When we use the backing device poll, our file
             * pointer is used (because the poll mechanism
             * needs it) but the backing device's private
             * data is used.  So we swap in the backing
             * device's private data just for the poll
             */
	        filp->private_data = ptd->file.private_data;
            mask = (*ptd->file.f_op->poll)(filp, wait);
	        filp->private_data = ptd;
        }
    } else {
        poll_wait(filp, &ptd->mq, wait);
        mask = 0;
    }

    #ifdef MUX_CHRDEV_DEBUG
    printk(KERN_INFO "%s device %d count %ld lock owner %d:%d poll%s%s\n", device_name, MINOR(filp->f_inode->i_rdev),
            file_count(&ptd->file), MAJOR(ptd->active_device), MINOR(ptd->active_device),
            ((mask & POLLIN) ? " POLLIN" : ""), ((mask & POLLOUT) ? " POLLOUT" : ""));
    #endif
    return mask;
}

static int device_fasync(int fd, struct file *filp, int on)
{
    struct muxdev_data *ptd = (struct muxdev_data *)filp->private_data;
    int rc = 0;
    if (ptd->file.f_op == NULL) {
        return -ENXIO;
    }
    mutex_lock(&ptd->mx);
    if (ptd->active_device != filp->f_inode->i_rdev) {
        if (ptd->active_device != 0) {
            if (filp->f_flags & O_NONBLOCK) {
                mutex_unlock(&ptd->mx);
                return -EAGAIN;
         } else {
                mutex_unlock(&ptd->mx);
                if (wait_event_interruptible(ptd->mq, (ptd->active_device == 0)) != 0) {
                    return -ERESTARTSYS;
                }
                mutex_lock(&ptd->mx);
           }
        }
        mod_timer(&ptd->timer, jiffies + timeout*HZ/1000);
        ptd->active_device = filp->f_inode->i_rdev;
    }
    if (ptd->file.f_op->fasync != NULL) {
        mutex_unlock(&ptd->mx);
        rc = (*ptd->file.f_op->fasync)(fd, &ptd->file, on);
        mutex_lock(&ptd->mx);
    }
    del_timer(&ptd->timer);
    ptd->active_device = 0;
    mutex_unlock(&ptd->mx);
    wake_up_interruptible(&ptd->mq);
    #ifdef MUX_CHRDEV_DEBUG
	printk(KERN_INFO "%s fasync()\n", device_name);
    #endif
	return rc;
}

static void device_show_fdinfo(struct seq_file *m, struct file *filp)
{
    struct muxdev_data *ptd = (struct muxdev_data *)filp->private_data;    
    const struct file *save_file;
    if (ptd->file.f_op == NULL || ptd->file.f_op->show_fdinfo == NULL) {
        return;
    }
    if (m != NULL) {
        save_file = m->file;
        m->file = &ptd->file;
    }
    #ifdef MUX_CHRDEV_DEBUG
	printk(KERN_INFO "%s show_fdinfo()\n", device_name);
    #endif
	(*ptd->file.f_op->show_fdinfo)(m, &ptd->file);
    if (m != NULL) {
        m->file = save_file;
    }
    return;
}

static struct file_operations fops = {
 	.llseek         = device_llseek,
    .read           = device_read,
	.write          = device_write,
	.open           = device_open,
	.release        = device_release,
	.poll           = device_poll,
	.unlocked_ioctl	= device_ioctl,
	.compat_ioctl   = device_compat_ioctl,
	.fasync         = device_fasync,
	.show_fdinfo    = device_show_fdinfo,
	.owner          = THIS_MODULE
};

static void muxdev_timer(struct timer_list *t) {
    struct muxdev_data *ptd = (struct muxdev_data *)from_timer(ptd, t, timer);
    #ifdef MUX_CHRDEV_DEBUG
	printk(KERN_INFO "%s Timer expired - removing minor %d lock\n", device_name, MINOR(ptd->active_device));
    #endif
    ptd->active_device = 0;
    wake_up_interruptible(&ptd->mq);
    return;    
}

static int __init mux_init(void)
{
    int i;
    if ((gptd = kzalloc(sizeof(struct muxdev_data), GFP_KERNEL)) == NULL) {
        return -ENOMEM;
    }
	if ((i = alloc_chrdev_region(&gptd->mux_dev, 0, N_DEVICES, device_name)) != 0) {
	    printk(KERN_ALERT "Registering char device failed: %d\n", i);
        kfree(gptd);
        return i;
    }
    for (i = 0; i < N_DEVICES; i++) {
        if ((gptd->pcdev[i] = cdev_alloc()) == NULL) {
            unregister_chrdev_region(gptd->mux_dev, N_DEVICES);
            return -EEXIST;
        }
        cdev_init(gptd->pcdev[i], &fops);
    }
    if ((i = cdev_add(gptd->pcdev[0], gptd->mux_dev, N_DEVICES)) != 0) {
        unregister_chrdev_region(gptd->mux_dev, N_DEVICES);
	    printk(KERN_ALERT "Adding char device failed: %d\n", i);
        kfree(gptd);
	    return i;
	}
    if ((gptd->pclass = class_create(THIS_MODULE, class_name)) == NULL) {
        for (i = 0; i < N_DEVICES; i++) {
            cdev_del(gptd->pcdev[i]);
        }
	    unregister_chrdev_region(gptd->mux_dev, N_DEVICES);
 	    printk(KERN_ERR "failed to create class %s\n", class_name);
        kfree(gptd);
        return -EINVAL;
    }
    for (i = 0; i < N_DEVICES; i++) {
        if ((gptd->muxdev_device[i] = device_create(gptd->pclass, NULL,
                gptd->mux_dev+i, gptd, "%s_%d", device_name,
                MINOR(gptd->mux_dev)+i)) == NULL) {
            class_destroy(gptd->pclass);
            for (i = 0; i < N_DEVICES; i++) {
                cdev_del(gptd->pcdev[i]);
            }
	        unregister_chrdev_region(gptd->mux_dev, N_DEVICES);
 	        printk(KERN_ERR "failed to create class device entries\n");
            kfree(gptd);
            return -EINVAL;
        }
        dev_set_drvdata(gptd->muxdev_device[i], (void *)gptd);
    }
    mutex_init(&gptd->mx);
    timer_setup(&gptd->timer, muxdev_timer, 0);
    init_waitqueue_head(&gptd->mq);
	printk(KERN_INFO "%s mux_chrdev assigned major number %d.\n", device_name, MAJOR(gptd->mux_dev));
	return 0;
}

static void __exit mux_exit(void)
{
    int i;
    del_timer_sync(&gptd->timer);
    for (i = 0; i < N_DEVICES; i++) {
        device_destroy(gptd->pclass,  gptd->mux_dev + i);
    }
    class_destroy(gptd->pclass);
    for (i = 0; i < N_DEVICES; i++) {
        cdev_del(gptd->pcdev[i]);
    }
    unregister_chrdev_region(gptd->mux_dev, N_DEVICES);
	printk(KERN_INFO "%s mux_chrdev removed.\n", device_name);
    kfree(gptd);
	return;
}

module_init(mux_init);
module_exit(mux_exit);
