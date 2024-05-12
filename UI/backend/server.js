// const fs = require("fs").promises;
// const chokidar = require("chokidar");
// const express = require("express");
// const { spawn } = require("child_process");
// const http = require("http");
// const { Server } = require("socket.io");
// var cors = require('cors')

// // Initialize Express app and other configurations
// const app = express();
// app.use(express.json());
// app.use(cors());

// const server = http.createServer(app);
// const io = new Server(server, {
//   cors: {
//     origin: "http://localhost:3000",
//   },
// });

// // Function to broadcast data to all connected Socket.io clients
// function broadcast(data) {
//   io.emit("log-update", data);
// }

// // Function to read logs from files and broadcast them
// async function readAndBroadcastLogs() {
//   try {
//     const eBPFLogs = await fs.readFile(
//       "/home/cheithanya/Desktop/Finalyearproject/eBPF/libbpf-bootstrap/examples/c/process_monitor_log.txt",
//       "utf8"
//     );
//     broadcast({ eBPFLogs });
//   } catch (error) {
//     console.error("Error reading logs:", error);
//   }
// }
// const validatePath = (path) => {
//   return /^\/[a-zA-Z0-9_\/.-]+$/.test(path);
// };
// // Function to handle deployment requests via Socket.IO
// io.on("connection", (socket) => {
//   console.log("Socket.io client connected");

//   socket.on("deployRequest", async (data) => {
//     console.log("Received deploy request:", data); 
//     const path = data.path;
//     if (!validatePath(path)) {
//         return socket.emit("deployError", "Invalid path provided.");
//     }

//     const command = "bash";
//     const args = ["-c", `sudo /home/cheithanya/Desktop/Finalyearproject/eBPF/libbpf-bootstrap/examples/c/monitor -p ${path}`];
//     const eBPFProcess = spawn(command, args);
//     const modelprocess=spawn(command,["-c","python3 ./model/main.py"])
    

//     eBPFProcess.on('error', (error) => {
//         console.error(`Spawn error: ${error}`);
//         socket.emit("deployError", `Error deploying eBPF program: ${error.message}`);
//     });

//     eBPFProcess.on('exit', (code, signal) => {
//         console.log(`eBPF process exited with code ${code} and signal ${signal}`);
//         readAndBroadcastLogs();
//         socket.emit("deploySuccess", "eBPF program and AI model deployed successfully.");
//     });

//     eBPFProcess.stdout.on('data', (data) => {
//         console.log(`stdout: ${data}`);
      
//     });
//     eBPFProcess.stderr.on('data', (data) => {
//         // console.error(`stderr: ${data}`);
//         socket.emit('message', data.toString());
        
//     });
//     modelprocess.stderr.on('data',(data)=>{
//       socket.emit('model', data.toString());
//     })
//   });

//   // Other Socket.IO event handlers...
// });

// // Start the server
// server.listen(5000, () => {
//   console.log("Server started on port 5000");
// });
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const { spawn } = require('child_process');
const fs = require("fs").promises;
const chokidar = require("chokidar");
const path = require('path');
var cors = require('cors')

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
  },
});
const port = 5000;

app.use(express.json());
app.use(cors());

let globalMonitoringProcess = null;
let honeyPotProcess = null;

// Function to broadcast data to all connected Socket.io clients
function broadcast(socket, eventName, data) {
  socket.emit(eventName, data);
}

// Function to read logs from files and broadcast them
async function readAndBroadcastLogs(socket) {
  try {
    const eBPFLogs = await fs.readFile(
      "/home/cheithanya/Desktop/Finalyearproject/eBPF/libbpf-bootstrap/examples/c/process_monitor_log.txt",
      "utf8"
    );
    broadcast(socket, "log-update", { eBPFLogs });
  } catch (error) {
    console.error("Error reading logs:", error);
  }
}

const validatePath = (path) => {
  return /^\/[a-zA-Z0-9_\/.-]+$/.test(path);
};

io.on('connection', (socket) => {
    console.log('A user connected: ' + socket.id);

    // Global Monitoring Handlers
    socket.on('run-script', () => {
        if (globalMonitoringProcess == null) {
            globalMonitoringProcess = spawn('python', [path.join(__dirname, './globalMonitoring.py')]);
            socket.emit('process-id', `${globalMonitoringProcess.pid}`);

            globalMonitoringProcess.stdout.on('data', (data) => {
                broadcast(socket, 'message', data.toString());
            });

            globalMonitoringProcess.stderr.on('data', (data) => {
                broadcast(socket, 'message', data.toString());
            });

            globalMonitoringProcess.on('close', (code) => {
                broadcast(socket, 'message', `Global Monitoring process stopped with code ${code}`);
                globalMonitoringProcess = null;
            });
        }
    });

    socket.on('stop-script', () => {
        if (globalMonitoringProcess != null) {
            globalMonitoringProcess.kill();
            broadcast(socket, 'message', 'Global Monitoring process stopped');
            globalMonitoringProcess = null;
        }
    });

    // Honey Pot Monitoring Handlers
    socket.on('run-honeypot', () => {
        if (honeyPotProcess == null) {
            honeyPotProcess = spawn('python', [path.join(__dirname, './honeyPotMonitoring.py')]);
            socket.emit('honeypot-process-id', `${honeyPotProcess.pid}`);

            honeyPotProcess.stdout.on('data', (data) => {
                broadcast(socket, 'honeypot-message', data.toString());
            });

            honeyPotProcess.stderr.on('data', (data) => {
                broadcast(socket, 'honeypot-message', data.toString());
            });

            honeyPotProcess.on('close', (code) => {
                broadcast(socket, 'honeypot-message', `Honey Pot process stopped with code ${code}`);
                honeyPotProcess = null;
            });
        }
    });

    socket.on('stop-honeypot', () => {
        if (honeyPotProcess != null) {
            honeyPotProcess.kill();
            broadcast(socket, 'honeypot-message', 'Honey Pot process stopped');
            honeyPotProcess = null;
        }
    });

    // Deployment Request Handler
    socket.on("deployRequest", async (data) => {
        console.log("Received deploy request:", data); 
        const path = data.path;
        if (!validatePath(path)) {
            return socket.emit("deployError", "Invalid path provided.");
        }

        const command = "bash";
        const args = ["-c", `sudo /home/cheithanya/Desktop/Finalyearproject/eBPF/libbpf-bootstrap/examples/c/monitor -p ${path}`];
        const eBPFProcess = spawn(command, args);
        const modelprocess = spawn(command, ["-c", "python3 ./model/main.py"]);

        eBPFProcess.on('error', (error) => {
            console.error(`Spawn error: ${error}`);
            socket.emit("deployError", `Error deploying eBPF program: ${error.message}`);
        });

        eBPFProcess.on('exit', (code, signal) => {
            console.log(`eBPF process exited with code ${code} and signal ${signal}`);
            readAndBroadcastLogs(socket);
            socket.emit("deploySuccess", "eBPF program and AI model deployed successfully.");
        });

        eBPFProcess.stdout.on('data', (data) => {
            console.log(`stdout: ${data}`);
            broadcast(socket, 'message', data.toString());
        });

        eBPFProcess.stderr.on('data', (data) => {
            broadcast(socket, 'message', data.toString());
        });

        modelprocess.stderr.on('data',(data)=>{
            broadcast(socket, 'model', data.toString());
        });
    });

    // Other event handlers...
});



server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
