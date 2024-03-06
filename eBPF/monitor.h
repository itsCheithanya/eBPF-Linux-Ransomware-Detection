//#include <time.h> 
#ifndef __MONITOR_H
#define __MONITOR_H

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 256
#define MAX_PROCESS_NAME_LEN 16
#define BUFFER_SIZE 100

typedef struct process_data {
 int pid;
 int ppid;
 int tgid;
 char process_name[MAX_PROCESS_NAME_LEN];
 int read_amount_bytes;
 int write_amount_bytes;
 int file_open_count;
 int file_read_count;
 int file_write_count;
 int file_unlink_count;
 int file_rename_count;
 int file_creat_count;
 int timestamp;
}process_data_t;


#endif /* __MONITOR_H */