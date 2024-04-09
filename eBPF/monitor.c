#include <argp.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h> 
#include <linux/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdint.h> // Include this header for uint64_t and uint32_t
#include "monitor.h"
#include "monitor.skel.h"
#include <unistd.h> // For getopt
#include <stdlib.h> // For exit
#include <libgen.h>



#define MAX_FILENAME_LEN 256
#define MAX_PROCESS_NAME_LEN 16
#define INTERVAL_SEC 1

// Global variable to store the directory path
char *directory_path = NULL;

// Global variable to control the loop
bool running = true;

// Signal handler for SIGINT (Ctrl+C)
void sigint_handler(int sig) {
    running = false;
}

// Function to parse command-line options
int parse_options(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
            case 'p':
                directory_path = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s -p <path of directory to monitor>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (directory_path == NULL) {
        fprintf(stderr, "Error: Path is required.\n");
        fprintf(stderr, "Usage: %s -p <path of directory to monitor>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    return 0;
}
// modify the populate_inode_map function to populate the inode number of the parent directory instead of the inode numbers of the files within the directory
void populate_inode_map(struct monitor_bpf *skel, const char *directory_path) {
    struct stat file_stat;
    char parent_dir[MAX_FILENAME_LEN];

    // Get the parent directory path
    strncpy(parent_dir, directory_path, sizeof(parent_dir) - 1);
    parent_dir[sizeof(parent_dir) - 1] = '\0'; // Ensure null-termination
    char *parent_dir_path = dirname(parent_dir);

    // Get the inode number of the parent directory
    if (stat(parent_dir_path, &file_stat) == -1) {
        fprintf(stderr, "Failed to stat parent directory: %s\n", parent_dir_path);
        return;
    }

    uint64_t inode_number = (uint64_t)file_stat.st_ino; // Use uint64_t instead of u64
    uint32_t value = 1; // Use uint32_t instead of u32
    fprintf(stdout, "Parent directory inode number: %lu\n", inode_number);
    bpf_map_update_elem(bpf_map__fd(skel->maps.inode_map), &inode_number, &value, BPF_ANY);
}

// void populate_inode_map(struct monitor_bpf *skel, const char *directory_path) {
//     DIR *dir;
//     struct dirent *entry;
//     struct stat file_stat;

//     dir = opendir(directory_path);
//     if (dir == NULL) {
//         fprintf(stderr, "Failed to open directory: %s\n", directory_path);
//         return;
//     }

//     while ((entry = readdir(dir)) != NULL) {
//         char file_path[MAX_FILENAME_LEN];
//         snprintf(file_path, sizeof(file_path), "%s/%s", directory_path, entry->d_name);
//         fprintf(stdout, "filename: %s\n", file_path);
//         if (stat(file_path, &file_stat) == -1) {
//             fprintf(stderr, "Failed to stat file: %s\n", file_path);
//             continue;
//         }

//         uint64_t inode_number = (uint64_t)file_stat.st_ino; // Use uint64_t instead of u64
//         uint32_t value = 1; // Use uint32_t instead of u32
//         fprintf(stdout, "filename inode number: %lu\n", inode_number);
//         bpf_map_update_elem(bpf_map__fd(skel->maps.inode_map), &inode_number, &value, BPF_ANY);
//     }

//     closedir(dir);
// }


void print_process_data(process_data_t *data) {
    FILE *logfile;
    logfile = fopen("process_monitor_log.txt", "a"); // Open the log file in append mode
    if (logfile == NULL) {
        printf("Error opening log file.\n");
        return;
    }

    

       printf("Timestamp : %llu\n", data->timestamp);
    printf("PID: %d\n", data->pid);
    printf("PPID: %d\n", data->ppid);
    printf("Process Name: %s\n", data->process_name);
    printf("Read Amount: %u\n", data->read_amount_bytes);
    printf("Write Amount: %u\n", data->write_amount_bytes);
    printf("File read Count: %u\n", data->file_read_count);
    printf("File write Count: %u\n", data->file_write_count);
    printf("File Open Count: %u\n", data->file_open_count);
    printf("File Create Count: %u\n", data->file_creat_count);
    printf("File Unlink Count: %u\n", data->file_unlink_count);
    printf("File Rename Count: %u\n", data->file_rename_count);
    printf("-------------------------\n");

    // Print to the log file
    fprintf(logfile,"Timestamp: %llu\n", data->timestamp);
    fprintf(logfile, "PID: %d\n", data->pid);
    fprintf(logfile, "Process Name: %s\n", data->process_name);
    fprintf(logfile, "Read Amount: %u\n", data->read_amount_bytes);
    fprintf(logfile, "Write Amount: %u\n", data->write_amount_bytes);
    fprintf(logfile, "File read Count: %u\n", data->file_read_count);
    fprintf(logfile, "File write Count: %u\n", data->file_write_count);
    fprintf(logfile, "File Open Count: %u\n", data->file_open_count);
    fprintf(logfile, "File Create Count: %u\n", data->file_creat_count);
    fprintf(logfile, "File Unlink Count: %u\n", data->file_unlink_count);
    fprintf(logfile, "File Rename Count: %u\n", data->file_rename_count);
    fprintf(logfile, "-------------------------\n");

    fclose(logfile); // Close the log file
}

int main(int argc, char ** argv) {

  parse_options(argc, argv);

  struct monitor_bpf * skel;
  int output_map, process_tree_map, output_final_map,err;
  int key;
 
  // Load eBPF program
  skel = monitor_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  // Load and attach eBPF program
  err = monitor_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
    goto cleanup;
  }

  err = monitor_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  // Get file descriptor of the output map
  output_map = bpf_map__fd(skel->maps.output);
  if (output_map < 0) {
    fprintf(stderr, "Failed to get output map FD\n");
    goto cleanup;
  }
  process_tree_map = bpf_map__fd(skel->maps.process_tree);
  if (process_tree_map < 0) {
    fprintf(stderr, "Failed to get output map FD\n");
    goto cleanup;
  }
   output_final_map = bpf_map__fd(skel->maps.output_final_map);
  if (output_final_map < 0) {
    fprintf(stderr, "Failed to get output map FD\n");
    goto cleanup;
  }
      // Populate the inode map with the inode numbers of the files within the specified directory
    populate_inode_map(skel, directory_path);


     // Set up signal handler for SIGINT
    signal(SIGINT, sigint_handler);

 while(running){
    // Iterate over existing entries in the map and form a output_final_map which stores the root process data information aggregated from its child processes
    key = -1;
    while (bpf_map_get_next_key(process_tree_map, & key, & key) == 0) {

      process_data_t  child_value={};
      process_data_t parent_value={};
      int value_process_tree;
      int ret1;
      bpf_map_lookup_elem(process_tree_map, & key, & value_process_tree);
      ret1  = bpf_map_lookup_elem(output_map, & key, & child_value);
      bpf_map_lookup_elem(output_map, & value_process_tree, & parent_value);

      if (ret1 == 0) {
        // Entry exists, process the data
        process_data_t new_parent_data={};
        process_data_t new_child_data={};
        if (bpf_map_lookup_elem(output_final_map, & value_process_tree, & new_parent_data) == -1) {
          //parent process entry does not exist in output_final map
          if (bpf_map_lookup_elem(output_final_map, & key, & new_child_data) == -1) {
            //child process entry doesnt exist in output_final map
            new_parent_data.timestamp= child_value.timestamp;
            new_parent_data.pid = child_value.pid;
            new_parent_data.ppid=child_value.ppid;
            strcpy(new_parent_data.process_name, parent_value.process_name);
            new_parent_data.read_amount_bytes = child_value.read_amount_bytes;
            new_parent_data.write_amount_bytes = child_value.write_amount_bytes;
            new_parent_data.file_read_count=child_value.file_read_count;
            new_parent_data.file_write_count=child_value.file_write_count;
            new_parent_data.file_open_count = child_value.file_open_count;
            new_parent_data.file_creat_count = child_value.file_creat_count;
            new_parent_data.file_unlink_count = child_value.file_unlink_count;
            new_parent_data.file_rename_count = child_value.file_rename_count;
            bpf_map_update_elem(output_final_map, & value_process_tree, & new_parent_data, BPF_ANY);
          } else {
            //child process entry exist in output_final map 
            new_parent_data.timestamp= child_value.timestamp;
            new_parent_data.pid = child_value.ppid;
            strcpy(new_parent_data.process_name, parent_value.process_name);
            new_parent_data.read_amount_bytes = child_value.read_amount_bytes + new_child_data.read_amount_bytes;
            new_parent_data.write_amount_bytes = child_value.write_amount_bytes + new_child_data.write_amount_bytes;
            new_parent_data.file_read_count=child_value.file_read_count+new_child_data.file_read_count;
            new_parent_data.file_write_count=child_value.file_write_count+new_child_data.file_write_count;
            new_parent_data.file_open_count = child_value.file_open_count + new_child_data.file_open_count;
            new_parent_data.file_creat_count = child_value.file_creat_count + new_child_data.file_creat_count;
            new_parent_data.file_unlink_count = child_value.file_unlink_count + new_child_data.file_unlink_count;
            new_parent_data.file_rename_count = child_value.file_rename_count + new_child_data.file_rename_count;
            bpf_map_update_elem(output_final_map, & value_process_tree, & new_parent_data, BPF_ANY);
            bpf_map_delete_elem(output_final_map, & key);
          }

        } else {
          //parent process entry exist in output_final map
          if (bpf_map_lookup_elem(output_final_map, & key, & new_child_data) == -1 ){//|| key == (__u32)value_process_tree) {
            //child process entry doesnt exist in output_final map
                        new_parent_data.timestamp= child_value.timestamp;
            new_parent_data.pid = child_value.pid;
                        new_parent_data.ppid=child_value.ppid;
            strcpy(new_parent_data.process_name, parent_value.process_name);
            new_parent_data.read_amount_bytes = new_parent_data.read_amount_bytes + child_value.read_amount_bytes;
            new_parent_data.write_amount_bytes = new_parent_data.write_amount_bytes + child_value.write_amount_bytes;
            new_parent_data.file_read_count= new_parent_data.file_read_count+child_value.file_read_count;
            new_parent_data.file_write_count= new_parent_data.file_write_count+child_value.file_write_count;
            new_parent_data.file_open_count = new_parent_data.file_open_count + child_value.file_open_count;
            new_parent_data.file_creat_count = new_parent_data.file_creat_count + child_value.file_creat_count;
            new_parent_data.file_unlink_count = new_parent_data.file_unlink_count + child_value.file_unlink_count;
            new_parent_data.file_rename_count = new_parent_data.file_rename_count + child_value.file_rename_count;
            bpf_map_update_elem(output_final_map, & value_process_tree, & new_parent_data, BPF_ANY);

          } else {
            //child process entry exist in output_final map 
                        new_parent_data.timestamp= child_value.timestamp;
              new_parent_data.pid = child_value.pid;
                        new_parent_data.ppid=child_value.ppid;
            strcpy(new_parent_data.process_name, parent_value.process_name);
            new_parent_data.read_amount_bytes = new_parent_data.read_amount_bytes + child_value.read_amount_bytes + new_child_data.read_amount_bytes;
            new_parent_data.write_amount_bytes = new_parent_data.write_amount_bytes + child_value.write_amount_bytes + new_child_data.write_amount_bytes;
            new_parent_data.file_read_count= new_parent_data.file_read_count+child_value.file_read_count+new_child_data.file_read_count;
            new_parent_data.file_write_count= new_parent_data.file_write_count+child_value.file_write_count+new_child_data.file_write_count;
            new_parent_data.file_open_count = new_parent_data.file_open_count + child_value.file_open_count + new_child_data.file_open_count;
            new_parent_data.file_creat_count = new_parent_data.file_creat_count + child_value.file_creat_count + new_child_data.file_creat_count;
            new_parent_data.file_unlink_count = new_parent_data.file_unlink_count + child_value.file_unlink_count + new_child_data.file_unlink_count;
            new_parent_data.file_rename_count = new_parent_data.file_rename_count + child_value.file_rename_count + new_child_data.file_rename_count;
            bpf_map_update_elem(output_final_map, & value_process_tree, & new_parent_data, BPF_ANY);
            bpf_map_delete_elem(output_final_map, & key);

          }

        }

        //remove the entry in output map and process_tree map for the the  
        bpf_map_delete_elem(output_map, & key);
        bpf_map_delete_elem(process_tree_map, & key);

      }
      if (ret1 < 0 ) {
        if (errno == ENOENT) break;
        fprintf(stderr, "Error while reading output map\n");
        goto cleanup;

      }
    }

 
    // Iterate over existing entries in the output_final_map and print the data
    key = -1;
   
    while (bpf_map_get_next_key(output_final_map, & key, & key) == 0) {
      process_data_t value={};
      if (bpf_map_lookup_elem(output_final_map, & key, & value) == 0) {
        print_process_data(&value);
        bpf_map_delete_elem(output_final_map, &key);
      } else {
        fprintf(stderr, "Error while reading output_final_map\n" );
        goto cleanup;
      }
     // sleep(INTERVAL_SEC);
    }

  }
 
  

  cleanup:
    monitor_bpf__destroy(skel);
  return err != 0;
}
