#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "monitor.h"



//pid_t min_pid=0; //minimum pid value
typedef enum event_type {
    T_OPEN = 0,
    T_CREATE = 1,
    T_READ = 2,
    T_WRITE = 3,
    T_UNLINK=4,
    T_RENAME=5,
    EVENT_TYPES,        // counts the number of event types
} event_type_t;



struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value, process_data_t);
} output SEC(".maps");

struct  {
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key, u64);
  __type(value, u32);
   __uint(max_entries, 8192);
}inode_map SEC(".maps")  ;


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value, int);
} process_tree SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value, process_data_t);
} output_final_map SEC(".maps");


static inline int capture_data(int processid,const char *file_name, int amount,event_type_t event) {
    process_data_t data;
    __builtin_memset(&data,0,sizeof(data));
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    // Capture PID, PPID, and process name
    int pid = task->pid;  // Make a copy of task->pid to 
    data.pid = pid;
    int ppid= task->parent->pid; // Make a copy of task->parent->pid to 
    bpf_printk("inside capture func pid = %d,PID = %d, PPID=%d,event =%d,amount =%d,filename = %s\n", processid,pid,ppid,event,amount,file_name);
    data.ppid =ppid; 
    data.tgid= task->tgid;

    bpf_probe_read_str(&data.process_name, sizeof(data.process_name), task->comm);
    data.timestamp=bpf_ktime_get_ns();

    // Capture file name
    //bpf_probe_read_str(&data.file_name, sizeof(data.file_name), file_name);

    // Capture amount
    if(event==2){
    // read event
             process_data_t *old_data;
             old_data=bpf_map_lookup_elem(&output,&pid);
              if (old_data == NULL) {
                 data.read_amount_bytes=amount;
                data.file_read_count=1;

              }else{
                 if(old_data->read_amount_bytes){
                    data.read_amount_bytes=old_data->read_amount_bytes+amount;
                    data.file_read_count=old_data->file_read_count+1;
                  }else{
                    data.read_amount_bytes=amount;
                    data.file_read_count=1;
                  }
              }
                
    }else if(event==3){
        //write event
         process_data_t *old_data;
             old_data=bpf_map_lookup_elem(&output,&pid);
             if(old_data==NULL){
                    data.write_amount_bytes=amount;
                    data.file_write_count=1;
             }else{
                  if(old_data->write_amount_bytes){
                data.write_amount_bytes=old_data->write_amount_bytes+amount;
                data.file_write_count=old_data->file_write_count+1;
                }else{
                data.write_amount_bytes=amount;
                data.file_write_count=1;

               }
             }
          
    }else{
        //event other than write and read
        if(event==0){
            //open 
             process_data_t *old_data;
             old_data=bpf_map_lookup_elem(&output,&pid);
             if(old_data==NULL){
                data.file_open_count=1;
             }else{
                     if(old_data->file_open_count){
                data.file_open_count=old_data->file_open_count+1;
               }else{
                data.file_open_count=1;
                }
             }
         
        }
           if(event==1){
            //create
            process_data_t *old_data;
             old_data=bpf_map_lookup_elem(&output,&pid);
             if(old_data==NULL){
                    data.file_creat_count=1;
             }else{
                     if(old_data->file_creat_count){
                data.file_creat_count=old_data->file_creat_count+1;
            }else{
                data.file_creat_count=1;
            }
             }
          
        }
          if(event==4){
            //unlink
            process_data_t *old_data;
             old_data=bpf_map_lookup_elem(&output,&pid);
             if(old_data==NULL){
                    data.file_unlink_count=1;
             }else{
                   if(old_data->file_unlink_count){
                data.file_unlink_count=old_data->file_unlink_count+1;
            }else{
                data.file_unlink_count=1;
            }
             }
       }
           
        
           if(event==5){
            //rename
            process_data_t *old_data;
             old_data=bpf_map_lookup_elem(&output,&pid);
             if(old_data==NULL){
                     data.file_rename_count=1;
             }else{
                 if(old_data->file_rename_count){
                data.file_rename_count=old_data->file_rename_count+1;
                }else{
                data.file_rename_count=1;
                }
             }
        
        }
    }
// bpf_printk("Event ENTRY pid = %d, ppid = %d, tgid = %d, process_name = %s, read_amount_bytes = %d, file_read_count = %d, write_amount_bytes = %d, file_write_count = %d, file_open_count = %d, file_creat_count = %d, file_unlink_count = %d, file_rename_count = %d\n",
//            pid, data.ppid, data.tgid, data.process_name, data.read_amount_bytes, data.file_read_count, data.write_amount_bytes, data.file_write_count, data.file_open_count, data.file_creat_count, data.file_unlink_count, data.file_rename_count);

    bpf_map_update_elem(&output, &pid, &data, BPF_ANY);
    bpf_map_update_elem(&process_tree, &pid, &ppid, BPF_ANY);
    
    
    return 0;
}


// extern ssize_t vfs_read(struct file *, char __user *, size_t, loff_t *);
// extern ssize_t vfs_write(struct file *, const char __user *, size_t, loff_t *);
// ssize_t vfs_iter_read(struct file *file, struct iov_iter *iter, loff_t *ppos,
// 		rwf_t flags);
// ssize_t vfs_iter_write(struct file *file, struct iov_iter *iter, loff_t *ppos,
// 		rwf_t flags);
SEC("kprobe/vfs_read")
int kprobe__vfs_read(struct pt_regs *ctx) {
    int amount = (int)PT_REGS_PARM3(ctx);
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    u64 inode_number = BPF_CORE_READ(dentry, d_inode, i_ino);

    // Get parent directory inode number
    struct dentry *parent_dentry = BPF_CORE_READ(dentry, d_parent);
    u64 parent_inode_number = BPF_CORE_READ(parent_dentry, d_inode, i_ino);
    // bpf_printk("Parent inode number: %llu\n", parent_inode_number);

    u32 *inode_exists = bpf_map_lookup_elem(&inode_map, &parent_inode_number);
    if (inode_exists) {
        const char *filename = (const char *)BPF_CORE_READ(dentry, d_name.name);
        bpf_printk("KPROBE read ENTRY pid = %d, filename = %s\n", bpf_get_current_pid_tgid() >> 32, filename);
        return capture_data(bpf_get_current_pid_tgid() >> 32, filename, amount, T_READ);
    }

    return 0;
}
SEC("kprobe/vfs_write")
int kprobe__vfs_write(struct pt_regs *ctx) {
    int amount = (int)PT_REGS_PARM3(ctx);
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    u64 inode_number = BPF_CORE_READ(dentry, d_inode, i_ino);

    // Get parent directory inode number
    struct dentry *parent_dentry = BPF_CORE_READ(dentry, d_parent);
    u64 parent_inode_number = BPF_CORE_READ(parent_dentry, d_inode, i_ino);
    // bpf_printk("Parent inode number: %llu\n", parent_inode_number);

    u32 *inode_exists = bpf_map_lookup_elem(&inode_map, &parent_inode_number);
    if (inode_exists) {
        const char *filename = (const char *)BPF_CORE_READ(dentry, d_name.name);
        bpf_printk("KPROBE write ENTRY   inode number= %llu, fpid = %d, filename = %s\n",inode_number, bpf_get_current_pid_tgid() >> 32, filename);
        return capture_data(bpf_get_current_pid_tgid() >> 32, filename, amount, T_WRITE);
    }

    return 0;
}
SEC("kprobe/vfs_iter_write")
int kprobe__vfs_iter_write(struct pt_regs *ctx) {
    int amount = (int)PT_REGS_PARM3(ctx);
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    u64 inode_number = BPF_CORE_READ(dentry, d_inode, i_ino);

 // Get parent directory inode number
    struct dentry *parent_dentry = BPF_CORE_READ(dentry, d_parent);
    u64 parent_inode_number = BPF_CORE_READ(parent_dentry, d_inode, i_ino);
    // bpf_printk("Parent inode number: %llu\n", parent_inode_number);

    u32 *inode_exists = bpf_map_lookup_elem(&inode_map, &parent_inode_number);
    if (inode_exists) {
        const char *filename = (const char *)BPF_CORE_READ(dentry, d_name.name);
        bpf_printk("KPROBE write ENTRY   inode number= %llu, fpid = %d, filename = %s\n",inode_number, bpf_get_current_pid_tgid() >> 32, filename);
        return capture_data(bpf_get_current_pid_tgid() >> 32, filename, amount, T_WRITE);
    }

    return 0;
}

// struct my_syscalls_enter_write {
// unsigned short common_type;
// unsigned char common_flags;
// unsigned char common_preempt_count;
// int common_pid;
// int __syscall_nr;
// 	unsigned int fd;	
// 	const char * buf;	
// 	size_t count;
// };

// SEC("tp/syscalls/sys_enter_write")
// int handle_tp(struct my_syscalls_enter_write *ctx) {
//     char buf[255];
//     bpf_probe_read_user(&buf, sizeof(buf), (void *)ctx->buf);

//     unsigned int fd;
//     int count;
//     bpf_probe_read_user(&fd, sizeof(fd), &ctx->fd);
//     bpf_probe_read_user(&count, sizeof(count), &ctx->count);

//    // Attempt to get the current task structure
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
//     if (!task) {
//         return 0; // Task not found, skip
//     }

//     struct files_struct *files = task->files;
    
//     // Access the file descriptor table
//     struct fdtable* fdt;
//     bpf_probe_read(&fdt, sizeof(fdt), (void*)&files->fdt);
//     if (!fdt) {
//         return 0; // File descriptor table not found, skip
//     }

//     // Attempt to get the file structure from the file descriptor
//     struct file** fdd;
//     int ret = bpf_probe_read(&fdd, sizeof(fdd), (void*)&fdt->fd); 
//     if (ret) {
//         bpf_trace_printk("bpf_probe_read failed: %d\\n", ret);
//         return 0;
//     } 
//     struct file *file;
//     bpf_probe_read(&file, sizeof(file), (void*)&fdd[fd]);
//     if (!file) {
//         return 0; // File not found, skip
//     }

//     struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
//     if (!dentry) {
//         return 0; // Dentry not found, skip
//     }

//     u64 inode_number = BPF_CORE_READ(dentry, d_inode, i_ino);

//     u32 *inode_exists = bpf_map_lookup_elem(&inode_map, &inode_number);
//     if (inode_exists) {
//         const  char *filename = (const char*)BPF_CORE_READ(dentry, d_name.name);

//         bpf_printk("TRACEPOINT write ENTRY inode number= %llu, fpid = %d, filename = %s\n",
//                    inode_number, bpf_get_current_pid_tgid() >> 32, filename);

//         capture_data(filename, count, T_WRITE); 
//     }
//     return 0;
// }

// SEC("tp_btf/sys_enter_write")
// int handle_tp(struct trace_event_raw_sys_enter_write *ctx) {
//     unsigned int fd;
//     int count;
//     bpf_probe_read_user(&fd, sizeof(fd), &ctx->fd);
//     bpf_probe_read_user(&count, sizeof(count), &ctx->count);

    
//    // Attempt to get the current task structure
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
//     if (!task) {
//         return 0; // Task not found, skip
//     }

//     struct files_struct *files = task->files;
    
//     // Access the file descriptor table
//     struct fdtable* fdt;
//     bpf_probe_read(&fdt, sizeof(fdt), (void*)&files->fdt);
//     if (!fdt) {
//         return 0; // File descriptor table not found, skip
//     }

//     // Attempt to get the file structure from the file descriptor
//     struct file** fdd;
//     int ret = bpf_probe_read(&fdd, sizeof(fdd), (void*)&fdt->fd); 
//     if (ret) {
//         bpf_trace_printk("bpf_probe_read failed: %d\\n", ret);
//         return 0;
//     } 
//     struct file *file;
//     bpf_probe_read(&file, sizeof(file), (void*)&fdd[fd]);
//     if (!file) {
//         return 0; // File not found, skip
//     }

//     struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
//     if (!dentry) {
//         return 0; // Dentry not found, skip
//     }


//     u64 inode_number = BPF_CORE_READ(dentry, d_inode, i_ino);

//     u32 *inode_exists = bpf_map_lookup_elem(&inode_map, &inode_number);
//     if (inode_exists) {
//         const char *filename = BPF_CORE_READ(dentry, d_name.name);

//         bpf_printk("TRACEPOINT write ENTRY inode number= %llu, fpid = %d, filename = %s\n",
//                    inode_number, bpf_get_current_pid_tgid() >> 32, filename);

//         capture_data(filename, count, T_WRITE); 
//     }
//     return 0;
// }
//Kprobe for file creation operations
SEC("kprobe/vfs_create")
int kprobe__vfs_create(struct pt_regs *ctx) {
    struct inode *inode = (struct inode *)PT_REGS_PARM2(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM3(ctx);
    u64 inode_number = BPF_CORE_READ(inode, i_ino);

     // Get parent directory inode number
    struct dentry *parent_dentry = BPF_CORE_READ(dentry, d_parent);
    u64 parent_inode_number = BPF_CORE_READ(parent_dentry, d_inode, i_ino);
    // bpf_printk("Parent inode number: %llu\n", parent_inode_number);

    u32 *inode_exists = bpf_map_lookup_elem(&inode_map, &parent_inode_number);
    if (inode_exists) {
        const char *filename = (const char *)BPF_CORE_READ(dentry, d_name.name);
        bpf_printk("KPROBE create ENTRY pid = %d, filename = %s\n", bpf_get_current_pid_tgid() >> 32, filename);
        return capture_data(bpf_get_current_pid_tgid() >> 32, filename, 0, T_CREATE);
    }
return 0;
}
// int vfs_create(struct mnt_idmap *, struct inode *,
// 	       struct dentry *, umode_t, bool);

//Kprobe for file deletion operations
SEC("kprobe/vfs_unlink")
int unlink(struct pt_regs *ctx) {
    struct dentry *dentry=(void *)PT_REGS_PARM3(ctx);
    u64 inode_number = BPF_CORE_READ(dentry, d_inode, i_ino);

      // Get parent directory inode number
    struct dentry *parent_dentry = BPF_CORE_READ(dentry, d_parent);
    u64 parent_inode_number = BPF_CORE_READ(parent_dentry, d_inode, i_ino);
    // bpf_printk("Parent inode number: %llu\n", parent_inode_number);

    u32 *inode_exists = bpf_map_lookup_elem(&inode_map, &parent_inode_number);
    if (inode_exists) {
        // The inode is in the watch list, proceed with capturing data
        const char *filename = (const char *)BPF_CORE_READ(dentry, d_name.name);
        bpf_printk("KPROBE unlink ENTRY pid = %d, filename = %s\n", bpf_get_current_pid_tgid() >> 32, filename);
        event_type_t event = T_UNLINK;
        return capture_data(bpf_get_current_pid_tgid() >> 32, filename, 0, event);
    }

    return 0; // Not in the watch list, do nothing

}


// Kprobe for file renaming operations
SEC("kprobe/vfs_rename")
int kprobe__vfs_rename(struct pt_regs *ctx) {
    struct renamedata *rd = (struct renamedata *)PT_REGS_PARM1(ctx);
    struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);
    u64 old_inode_number = BPF_CORE_READ(old_dentry, d_inode, i_ino);

   // Get parent directory inode number
    struct dentry *parent_dentry = BPF_CORE_READ(old_dentry, d_parent);
    u64 parent_inode_number = BPF_CORE_READ(parent_dentry, d_inode, i_ino);
    // bpf_printk("Parent inode number: %llu\n", parent_inode_number);
    // Check if the old inode is in the watch list
    u32 *inode_exists = bpf_map_lookup_elem(&inode_map, &parent_inode_number);
        if (inode_exists) {
        const char *old_filename = (const char *)BPF_CORE_READ(old_dentry, d_name.name);
        bpf_printk("KPROBE rename old inode number= %llu, filename = %s\n", old_inode_number, old_filename);
        capture_data(bpf_get_current_pid_tgid() >> 32, old_filename, 0, T_RENAME);
    }
     return 0;
}

SEC("kprobe/vfs_open")
int bpf_prog1(struct pt_regs *ctx) {
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    struct file *file = (struct file *)PT_REGS_PARM2(ctx);
        struct dentry *dentry = BPF_CORE_READ(path, dentry);
    u64 inode_number = BPF_CORE_READ(dentry, d_inode, i_ino);

  
   // Get parent directory inode number
    struct dentry *parent_dentry = BPF_CORE_READ(dentry, d_parent);
    u64 parent_inode_number = BPF_CORE_READ(parent_dentry, d_inode, i_ino);
    // bpf_printk("Parent inode number: %llu\n", parent_inode_number);
    // Check if the old inode is in the watch list
    u32 *inode_exists = bpf_map_lookup_elem(&inode_map, &parent_inode_number);

    if (inode_exists) {
        const char *filename = (const char *)BPF_CORE_READ(dentry, d_name.name);
        bpf_printk("KPROBE open  inode number= %llu, filename = %s\n", inode_number, filename);
        return capture_data(bpf_get_current_pid_tgid() >> 32, filename, 0, T_OPEN);
    }

    return 0;
}
// /**
//  * vfs_open - open the file at the given path
//  * @path: path to open
//  * @file: newly allocated file with f_flag initialized
//  * @cred: credentials to use
//  */
// int vfs_open(const struct path *path, struct file *file,
// 	     const struct cred *cred)
// {
// 	struct inode *inode = vfs_select_inode(path->dentry, file->f_flags);

// 	if (IS_ERR(inode))
// 		return PTR_ERR(inode);

// 	file->f_path = *path;
// 	retur do_dentry_open(file, inode, NULL, cred);
// }



char LICENSE[] SEC("license") = "Dual BSD/GPL";







