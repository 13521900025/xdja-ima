#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/parser.h>
#include <linux/security.h>

#include "ima.h"

#define MAX_PATHLIST 10

#define WHITE0 "/usr/bin/"
#define WHITE1 "/bin/"
#define WHITE2 "/usr/sbin/"
#define WHITE3 "/sbin/"
#define WHITE4 "/usr/bin/evmctl"

LIST_HEAD(ima_path_list);
static int ima_path_list_count = 0;

static ssize_t ima_path_show_measurements_count(struct file *filp,
					   char __user *buf,
					   size_t count, loff_t *ppos)
{
	char tmpbuf[10];
	ssize_t len;

	len = scnprintf(tmpbuf, 10, "%d\n", ima_path_list_count);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, len);
}

static const struct file_operations ima_path_measurements_count_ops = {
	.read = ima_path_show_measurements_count,
	.llseek = generic_file_llseek,
};

/* returns pointer to hlist_node */
static void *ima_path_measurements_start(struct seq_file *m, loff_t *pos)
{
	loff_t l = *pos;
	struct ima_path_struct *_ima_path;

	/* we need a lock since pos could point beyond last element */
	rcu_read_lock();
	list_for_each_entry_rcu(_ima_path, &ima_path_list, ima_paths) {
		if (!l--) {
			rcu_read_unlock();
			return _ima_path;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static void *ima_path_measurements_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct ima_path_struct *_ima_path = v;

	/* lock protects when reading beyond last element
	 * against concurrent list-extension
	 */
	rcu_read_lock();
	_ima_path = list_entry_rcu(_ima_path->ima_paths.next,
			    struct ima_path_struct, ima_paths);
	rcu_read_unlock();
	(*pos)++;

	return (&_ima_path->ima_paths == &ima_path_list) ? NULL : _ima_path;
}

static void ima_path_measurements_stop(struct seq_file *m, void *v)
{
}

/* print in ascii */
static int ima_path_ascii_measurements_show(struct seq_file *m, void *v)
{
	/* the list never shrinks, so we don't need a lock here */
	struct ima_path_struct * _ima_path = v;

	if (_ima_path == NULL)
		return -1;

	/* 1th:  path name */
	seq_printf(m, "%s \n", _ima_path->path);

	return 0;
}

static const struct seq_operations ima_path_ascii_measurements_seqops = {
	.start = ima_path_measurements_start,
	.next = ima_path_measurements_next,
	.stop = ima_path_measurements_stop,
	.show = ima_path_ascii_measurements_show
};

static ssize_t ima_path_ascii_measurements_write(struct file *file, const char __user *buf,
	size_t datalen, loff_t *ppos)
{
	char *data = NULL;
	ssize_t result;
	struct ima_path_struct * a;

	if(!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if(ima_path_list_count >= MAX_PATHLIST)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	if(datalen <= 0 || datalen > PATH_MAX)
		return -EINVAL;

	data = kmalloc(datalen, GFP_KERNEL);
	if(!data)
		return -ENOMEM;

	result = -EFAULT;
	if(copy_from_user(data, buf, datalen))
		goto out;

	*(data + datalen-1) = '\0';

	result = -EINVAL;
#define WHITE(PATH) \
	if(strncmp(PATH,data,strlen(data)) == 0) \
		goto out;

	WHITE(WHITE0)
	WHITE(WHITE1)
	WHITE(WHITE2)
	WHITE(WHITE3)
	WHITE(WHITE4)

	result = -EEXIST;
	if(!ima_path_cmp(data))
		goto out;

	a = kzalloc(sizeof(struct ima_path_struct), GFP_KERNEL);
	if (likely(a != NULL)) {
		strncpy(a->path,data,datalen);
		INIT_LIST_HEAD(&a->ima_paths);
		list_add_tail_rcu(&a->ima_paths, &ima_path_list);
		ima_path_list_count++;
		result = datalen;
	}
out:
	kfree(data);
	return result;
}

static int ima_path_ascii_measurements_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ima_path_ascii_measurements_seqops);
}

static const struct file_operations ima_path_ascii_measurements_ops = {
	.open = ima_path_ascii_measurements_open,
	.write = ima_path_ascii_measurements_write,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static struct dentry *ima_path_dir;
static struct dentry *ima_path_ascii_runtime_measurements;
static struct dentry *ima_path_ascii_runtime_measurements_count;

int ima_path_cmp(const char* path)
{
	struct ima_path_struct *_ima_path;
	
	rcu_read_lock();
	list_for_each_entry_rcu(_ima_path, &ima_path_list, ima_paths) {
		if (strncmp(path,_ima_path->path,strlen(_ima_path->path)) == 0) {
			rcu_read_unlock();
			return 0;
		}
	}
	rcu_read_unlock();

	return -1;
}

int __init ima_path_fs_init(struct dentry *parent)
{
	struct ima_path_struct * a;

	ima_path_dir = securityfs_create_dir("ima_policy_paths", parent);
	if (IS_ERR(ima_path_dir))
		return -1;

	ima_path_ascii_runtime_measurements =
	    securityfs_create_file("ima_path_ascii_runtime_measurements",
				   S_IRUSR | S_IRGRP | S_IWUSR, ima_path_dir, NULL,
				   &ima_path_ascii_measurements_ops);
	if (IS_ERR(ima_path_ascii_runtime_measurements))
		goto out;

	ima_path_ascii_runtime_measurements_count =
	securityfs_create_file("ima_path_ascii_runtime_measurements_count",
				S_IRUSR | S_IRGRP, ima_path_dir, NULL,
				&ima_path_measurements_count_ops);
	if (IS_ERR(ima_path_ascii_runtime_measurements_count))
		goto out;

#define init_ima_pathlist(PATH) 		\
	{	\
		if(strlen(PATH) > 0 &&         \
			strlen(PATH) < PATH_MAX && \
			ima_path_cmp(PATH)){ \
			a = kzalloc(sizeof(struct ima_path_struct), GFP_KERNEL); \
			if (likely(a != NULL)) { \
				strncpy(a->path,PATH,strlen(PATH)+1); \
				INIT_LIST_HEAD(&a->ima_paths); \
				list_add_tail_rcu(&a->ima_paths, &ima_path_list); \
				ima_path_list_count++; \
			} \
		} \
	}

	init_ima_pathlist(CONFIG_IMA_PATH_APPRAISE0)
	init_ima_pathlist(CONFIG_IMA_PATH_APPRAISE1)
	init_ima_pathlist(CONFIG_IMA_PATH_APPRAISE2)
	return 0;
out:
	securityfs_remove(ima_path_ascii_runtime_measurements_count);
	securityfs_remove(ima_path_ascii_runtime_measurements);
	securityfs_remove(ima_path_dir);
	return -1;
}
