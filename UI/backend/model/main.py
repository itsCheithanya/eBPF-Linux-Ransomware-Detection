import time
import os
import signal
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle
import numpy as np
from sklearn.exceptions import InconsistentVersionWarning
import warnings
import sys

# Minimum number of entries per pid
MIN_ENTRIES = 10

# Function to parse a single log entry
def parse_log_entry(entry):
    log_entry = {}
    lines = entry.strip().split('\n')
    for line in lines:
        parts = line.split(': ')
        if len(parts) == 2:  # Ensure we have key and value
            key, value = parts
            log_entry[key] = int(value) if key != 'Process Name' else value
    return log_entry

# Function to read and accumulate logs for each PID
def read_accumulate_logs(file_path):
    accumulated_logs = {}
    with open(file_path, 'r') as file:
        log_entry = ""
        for line in file:
            if line.strip() == '-------------------------':
                entry = parse_log_entry(log_entry)
                if len(entry) == 0:
                    continue
                pid = entry['PID']
                if pid not in accumulated_logs:
                    accumulated_logs[pid] = []
                accumulated_logs[pid].append(entry)
                log_entry = ""
            else:
                log_entry += line
    return accumulated_logs

# Load trained Random Forest classifier
clf = RandomForestClassifier()
# Load trained Random Forest classifier
try:
    with open('/home/cheithanya/Desktop/Finalyearproject/UI/backend/model/trained_rf_model.pkl', 'rb') as file:
        clf = pickle.load(file)  # Assuming you saved the model using pickle
except InconsistentVersionWarning as w:
    print(w.original_sklearn_version)

with open('/home/cheithanya/Desktop/Finalyearproject/eBPF/libbpf-bootstrap/examples/c/model_output.txt', "w") as f:
    f.truncate(0)

while True:
    # Read and accumulate logs
    accumulated_logs = read_accumulate_logs('/home/cheithanya/Desktop/Finalyearproject/eBPF/libbpf-bootstrap/examples/c/process_monitor_log.txt')

    ransomware_pids = []
    for pid, logs in accumulated_logs.items():
        # Convert accumulated logs to DataFrame
        df = pd.DataFrame(logs)
        
        if df.shape[0] > MIN_ENTRIES:
            print(str(pid))
            print(df.shape[0])
            # Feature extraction
            features = df[['Write Amount', 'File write Count', 'File Open Count', 'File Unlink Count', 'File Rename Count']]
        
            # Predict using the trained classifier
            predictions = clf.predict(features)

            # Find the unique elements and their frequencies
            unique_values, frequencies = np.unique(predictions, return_counts=True)

            # Find the index of the element with the highest frequency
            index_of_max_frequency = np.argmax(frequencies)

            # Get the element with the highest frequency
            most_frequent_element = unique_values[index_of_max_frequency]

            if most_frequent_element == "ransomware":
                ransomware_pids.append(pid)
                try:
                    print(f"PID {pid} terminated RANSOMWARE",file=sys.stderr)
                    os.kill(pid, signal.SIGTERM)
                    
                except :
                    print(f"PID {pid} does not exist",file=sys.stderr)
            

            # Check if any prediction is ransomware
            print(f"PID {pid} is {most_frequent_element}", file=sys.stderr)

    # Log ransomware PIDs to a file
    with open('ransomware_pids.txt', 'a') as file:
        for pid in ransomware_pids:
            file.write(f"{pid}\n")
    
    # Wait for 10 seconds before reading logs again
    # time.sleep(10)
    # break
