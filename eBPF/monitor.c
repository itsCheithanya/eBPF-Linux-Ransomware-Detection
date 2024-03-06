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
#include "monitor.h"
#include "monitor.skel.h"

#define MAX_FILENAME_LEN 256
#define MAX_PROCESS_NAME_LEN 16
#define INTERVAL_SEC 10

// Global variable to control the loop
bool running = true;

// Signal handler for SIGINT (Ctrl+C)
void sigint_handler(int sig) {
    running = false;
}


void print_process_data(process_data_t * data) {
  //output it to a file and stoud
  printf("PID: %d\n", data->pid);
  printf("Process Name: %s\n", data->process_name);
  printf("Read Amount: %u\n", data->read_amount_bytes);
  printf("Write Amount: %u\n", data->write_amount_bytes);
  printf("File Open Count: %u\n", data->file_open_count);
  printf("File Create Count: %u\n", data->file_creat_count);
  printf("File Unlink Count: %u\n", data->file_unlink_count);
  printf("File Rename Count: %u\n", data->file_rename_count);

  printf("-------------------------\n");

}

int main(int argc, char ** argv) {
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

     // Set up signal handler for SIGINT
    signal(SIGINT, sigint_handler);

 while(running){
    // Iterate over existing entries in the map and form a output_final_map which stores the root process data information aggregated from its child processes
    key = -1;
    while (bpf_map_get_next_key(process_tree_map, & key, & key) == 0) {

      process_data_t  child_value, parent_value;
      int value_process_tree;
      int ret1;
      bpf_map_lookup_elem(process_tree_map, & key, & value_process_tree);
      ret1  = bpf_map_lookup_elem(output_map, & key, & child_value);
      bpf_map_lookup_elem(output_map, & value_process_tree, & parent_value);

      if (ret1 == 0) {
        // Entry exists, process the data
        process_data_t new_parent_data;
        process_data_t new_child_data;
        if (bpf_map_lookup_elem(output_final_map, & value_process_tree, & new_parent_data) == -1) {
          //parent process entry does not exist in output_final map
          if (bpf_map_lookup_elem(output_final_map, & key, & new_child_data) == -1) {
            //child process entry doesnt exist in output_final map
            new_parent_data.pid = child_value.ppid;
            // new_parent_data.ppid = parent_value.ppid;
            strcpy(new_parent_data.process_name, parent_value.process_name);
            new_parent_data.read_amount_bytes = child_value.read_amount_bytes;
            new_parent_data.write_amount_bytes = child_value.write_amount_bytes;
            new_parent_data.file_open_count = child_value.file_open_count;
            new_parent_data.file_creat_count = child_value.file_creat_count;
            new_parent_data.file_unlink_count = child_value.file_unlink_count;
            new_parent_data.file_rename_count = child_value.file_rename_count;
            bpf_map_update_elem(output_final_map, & value_process_tree, & new_parent_data, BPF_ANY);
          } else {
            //child process entry exist in output_final map 
            new_parent_data.pid = child_value.ppid;
            // new_parent_data.ppid = parent_value.ppid;
            strcpy(new_parent_data.process_name, parent_value.process_name);
            new_parent_data.read_amount_bytes = child_value.read_amount_bytes + new_child_data.read_amount_bytes;
            new_parent_data.write_amount_bytes = child_value.write_amount_bytes + new_child_data.write_amount_bytes;
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
            new_parent_data.pid = child_value.ppid;
            // new_parent_data.ppid = parent_value.ppid;
            strcpy(new_parent_data.process_name, parent_value.process_name);
            new_parent_data.read_amount_bytes = new_parent_data.read_amount_bytes + child_value.read_amount_bytes;
            new_parent_data.write_amount_bytes = new_parent_data.write_amount_bytes + child_value.write_amount_bytes;
            new_parent_data.file_open_count = new_parent_data.file_open_count + child_value.file_open_count;
            new_parent_data.file_creat_count = new_parent_data.file_creat_count + child_value.file_creat_count;
            new_parent_data.file_unlink_count = new_parent_data.file_unlink_count + child_value.file_unlink_count;
            new_parent_data.file_rename_count = new_parent_data.file_rename_count + child_value.file_rename_count;
            bpf_map_update_elem(output_final_map, & value_process_tree, & new_parent_data, BPF_ANY);

          } else {
            //child process entry exist in output_final map 
            new_parent_data.pid = child_value.ppid;
            // new_parent_data.ppid = parent_value.ppid;
            strcpy(new_parent_data.process_name, parent_value.process_name);
            new_parent_data.read_amount_bytes = new_parent_data.read_amount_bytes + child_value.read_amount_bytes + new_child_data.read_amount_bytes;
            new_parent_data.write_amount_bytes = new_parent_data.write_amount_bytes + child_value.write_amount_bytes + new_child_data.write_amount_bytes;
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
      process_data_t value;
      if (bpf_map_lookup_elem(output_final_map, & key, & value) == 0) {
        print_process_data(&value);
      } else {
        fprintf(stderr, "Error while reading output_final_map\n" );
        goto cleanup;
      }
      sleep(INTERVAL_SEC);
    }

  }
 
  

  cleanup:
    monitor_bpf__destroy(skel);
  return err != 0;
}