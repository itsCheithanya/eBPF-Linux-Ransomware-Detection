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

// struct my_kprobe_vfs_read_write {
//     unsigned short common_type;
//     unsigned char common_flags;
//     unsigned char common_preempt_count;
//     int common_pid;
//     const char *file_name;
//     int amount;
// };

struct my_syscalls_enter_rw {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned int fd;
    char *buf;
    size_t count;
};

SEC("tp/syscalls/sys_enter_write")
int tp_sys_enter_write(struct my_syscalls_enter_rw *ctx) {
 
    int amount=(int)ctx->count;
    char filename[]="samplefile";
    event_type_t event = T_WRITE;
    return capture_data( filename, amount, event);


    return 0;
}
SEC("tp/syscalls/sys_enter_read")
int tp_sys_enter_read(struct my_syscalls_enter_rw *ctx) {
  
    int amount=(int)ctx->count;
     char filename[]="samplefile";
    event_type_t event = T_READ;
    return capture_data( filename, amount, event);

    return 0;
}



// SEC("kprobe/vfs_read")
// int kprobe__vfs_read(struct my_kprobe_vfs_read_write *ctx) {
//     // Extract file name and amount from the context
//     const char *file_name = ctx->file_name;
//     int amount = ctx->amount;

//     // Add your logic here

//     // Call capture_data with file name and amount
//     event_type_t event = T_READ;
//     return capture_data( file_name, amount, event);
// }


// SEC("kprobe/vfs_write")
// int kprobe__vfs_write(struct my_kprobe_vfs_read_write *ctx) {
//     // Extract file name and amount from the context
//     const char *file_name = ctx->file_name;
//     int amount = ctx->amount;

//     // Add your logic here

//     // Call capture_data with file name and amount
//     event_type_t event = T_WRITE;
//     return capture_data( file_name, amount, event);
// }
// // Kprobe for file write operations
// SEC("kprobe/vfs_write")
// int kprobe__vfs_write(struct pt_regs *ctx) {
//     const char *file_name = NULL;
//     int amount = 0;
//     event_type_t event;

//     // Get file name and amount
//     bpf_probe_read(&file_name, sizeof(file_name), PT_REGS_PARM2(ctx));
//     amount = (int)PT_REGS_PARM3(ctx);
//     event=T_WRITE;
//     return capture_data(ctx, file_name, amount,event);
// }

// // Kprobe for file read operations
// SEC("kprobe/vfs_read")
// int kprobe__vfs_read(struct pt_regs *ctx) {
//     const char *file_name = NULL;
//     int amount = 0;
//     event_type_t event;

//     // Get file name and amount
//     bpf_probe_read(&file_name, sizeof(file_name), PT_REGS_PARM2(ctx));
//     amount = (int)PT_REGS_PARM3(ctx);
//     event=T_READ;

//     return capture_data(ctx, file_name, amount,event);
// }

// // Kprobe for file deletion operations
// SEC("kprobe/vfs_unlink")
// int kprobe__vfs_unlink(struct pt_regs *ctx) {
//     const char *file_name = NULL;
//     event_type_t event;
//     // Get file name
//     bpf_probe_read(&file_name, sizeof(file_name), PT_REGS_PARM1(ctx));
//     event=T_UNLINK;

//     return capture_data(ctx, file_name, 0,event);
// }

// // Kprobe for file renaming operations
// SEC("kprobe/vfs_rename")
// int kprobe__vfs_rename(struct pt_regs *ctx) {
//     const char *old_file_name = NULL;
//     const char *new_file_name = NULL;
//     event_type_t event;

//     // Get old file name
//     bpf_probe_read(&old_file_name, sizeof(old_file_name), PT_REGS_PARM1(ctx));
//     // Get new file name
//     bpf_probe_read(&new_file_name, sizeof(new_file_name), PT_REGS_PARM2(ctx));

//     event=T_RENAME;
//     return capture_data(ctx, old_file_name, 0,event);
    
// }

// // Kprobe for file opening operations
// SEC("kprobe/vfs_open")
// int kprobe__vfs_open(struct pt_regs *ctx) {
//     struct file *file = (struct file *)PT_REGS_RC(ctx);
//     struct dentry *dentry;
//     char file_name[MAX_FILENAME_LEN];
//     event_type_t event;

//     // Get file name
//     dentry = file->f_path.dentry;
//     bpf_probe_read(&file_name, sizeof(file_name), dentry->d_iname);
//     event=T_OPEN;

//     return capture_data(ctx, file_name, 0,event);
// }

char LICENSE[] SEC("license") = "Dual BSD/GPL";