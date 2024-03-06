#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "monitor.h"
//#include <linux/fs.h>


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
	__type(key, pid_t);
	__type(value, process_data_t);
} output SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, pid_t);
} process_tree SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, process_data_t);
} output_final_map SEC(".maps");


static inline int capture_data(const char *file_name, int amount,event_type_t event) {
    process_data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    // Capture PID, PPID, and process name
    int pid = task->pid;  // Make a copy of task->pid to 
    data.pid = pid;
    int ppid= task->parent->pid; // Make a copy of task->parent->pid to 
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
              }else{
                 if(old_data->read_amount_bytes){
                    data.read_amount_bytes=old_data->read_amount_bytes+amount;
                  }else{
                    data.read_amount_bytes=amount;
                  }
              }
                
    }else if(event==3){
        //write event
         process_data_t *old_data;
             old_data=bpf_map_lookup_elem(&output,&pid);
             if(old_data==NULL){
                    data.write_amount_bytes=amount;
             }else{
                  if(old_data->write_amount_bytes){
                data.write_amount_bytes=old_data->write_amount_bytes+amount;
                }else{
                data.write_amount_bytes=amount;
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
    bpf_map_update_elem(&output, &pid, &data, BPF_ANY);
    bpf_map_update_elem(&process_tree, &pid, &ppid, BPF_ANY);
    
    
    return 0;
}


struct my_kprobe_vfs_read_write {
    struct file *file;
    char  *buf;
    int count;
    //loff_t *pos;
};

SEC("kprobe/vfs_read")
int kprobe__vfs_read(struct my_kprobe_vfs_read_write *ctx) {
    // Extract arguments from the context
    struct file *file = ctx->file;
    char  *buf = ctx->buf;
    int count = ctx->count;
//    loff_t *pos = ctx->pos;

    // Extract file name from the 'file' structure
    char file_name[MAX_FILENAME_LEN]="sample";
    //bpf_probe_read_user(file_name, MAX_FILENAME_LEN, file->f_path.dentry->d_name.name);
    // Add your logic here

    // Call capture_data with file name, amount, and event
    event_type_t event = T_READ;
    return capture_data(file_name, count, event);
}

SEC("kprobe/vfs_write")
int kprobe__vfs_write(struct my_kprobe_vfs_read_write *ctx) {
    // Extract arguments from the context
    struct file *file = ctx->file;
    char  *buf = ctx->buf;
    int count = ctx->count;
    //loff_t *pos = ctx->pos;

    // Extract file name from the 'file' structure
    char file_name[MAX_FILENAME_LEN]="sample";
    //bpf_probe_read_user(file_name, MAX_FILENAME_LEN, file->f_path.dentry->d_name.name);
    // Add your logic here

    // Call capture_data with file name, amount, and event
    event_type_t event = T_WRITE;
    return capture_data(file_name, count, event);
}
SEC("kprobe/vfs_open")
int kprobe_vfs_open(struct pt_regs *ctx, const struct path *path, struct file *file) {
    // Extract relevant information from the function arguments
    const char *file_path = path->dentry->d_name.name;
    unsigned int flags = file->f_flags;

    // Call capture_data function with the extracted information
    event_type_t event = T_OPEN;
    return capture_data(file_path, 0, event);
}

SEC("kprobe/vfs_rename")
int kprobe_vfs_rename(struct pt_regs *ctx, struct renamedata *data) {
    // Extract relevant information from the function arguments
    const char *old_path = data->old_dentry->d_name.name;
    const char *new_path = data->new_dentry->d_name.name;

    // Call capture_data function with the extracted information
    event_type_t event = T_RENAME;
    return capture_data(old_path, 0, event);
}

SEC("kprobe/vfs_unlink")
int kprobe_vfs_unlink(struct pt_regs *ctx, struct mnt_idmap *mnt, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode) {
    // Extract relevant information from the function arguments
    const char *file_path = dentry->d_name.name;

    // Call capture_data function with the extracted information
    event_type_t event = T_UNLINK;
    return capture_data(file_path, 0,event);
}

SEC("kprobe/vfs_create")
int kprobe_vfs_create(struct pt_regs *ctx) {
    // Extract relevant information from the function arguments
    //const char *file_path = dentry->d_name.name;

    // Call capture_data function with the extracted information
    event_type_t event = T_CREATE;
    return capture_data("sample",0, event);
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";