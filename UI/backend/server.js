// const fs = require("fs").promises;
// const chokidar = require("chokidar");
// var cors = require('cors')
// const express = require("express");
// const { spawn } = require("child_process");
// const http = require("http"); // Use 'https' if you are using HTTPS
// const {Server} = require("socket.io");


// const app = express();
// app.use(express.json());
// app.use(cors());

// // Create an HTTP server from the express apps
// const server = http.createServer(app);
// const io = new Server(server,{
//     cors: {
//       origin: "http://localhost:3000",
//     }
//   });
// var monitorprocess=null

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
//    // const modelOutput = await fs.readFile("/path/to/pid_output.txt", "utf8");
//     broadcast({ eBPFLogs });
//   } catch (error) {
//     console.error("Error reading logs:", error);
//   }
// }

// // Validate the path to prevent command injection
// const validatePath = (path) => {
//   return /^\/[a-zA-Z0-9_\/.-]+$/.test(path);
// };
// app.get("/",(req,res)=>{
//     res.send("hello")
// })
// // // API to deploy the eBPF program
// // app.post("/api/deploy", (req, res) => {
// //   const path = req.body.path;
// //   if (!validatePath(path)) {
// //     return res.status(400).send("Invalid path provided.");
// //   }
// //   res.send("eBPF program and AI model deployed successfully.");

// //   const eBPFCommand = `sudo /home/cheithanya/Desktop/Finalyearproject/eBPF/libbpf-bootstrap/examples/c/monitor -p ${path}`;
// //   exec(eBPFCommand, (error, stdout, stderr) => {
// //     if (error) {
// //       console.error(`exec error: ${error}`);
// //       return res.status(500).send(`Error deploying eBPF program: ${stderr}`);
// //     } // Assume main.py also takes care of reading from `process_monitor_logs.txt`

// //     // exec("sudo /usr/bin/python3 main.py", (pyError, pyStdout, pyStderr) => {
// //     //   if (pyError) {
// //     //     console.error(`Python exec error: ${pyError}`);
// //     //     return res.status(500).send(`Error running Python model: ${pyStderr}`);
// //     //   } //   res.send(pyStdout); // Trigger reading logs and broadcasting after deployment
      
// //     // });
// //     readAndBroadcastLogs();
// //     res.send("eBPF program and AI model deployed successfully.");
// //   });
// // });

// app.post("/api/deploy", async (req, res) => {
//     console.log("Received deploy request:", req.body); 
//     const path = req.body.path;
//     if (!validatePath(path)) {
//         return res.status(400).send("Invalid path provided.");
//     }

//     // Define the command to execute the eBPF program
//     const command = "bash";
//     const args = ["-c", `sudo /home/cheithanya/Desktop/Finalyearproject/eBPF/libbpf-bootstrap/examples/c/monitor -p ${path}`];

//     // Spawn the child process
//     const eBPFProcess = spawn(command, args);

//     // Listen for the 'error' event to handle errors
//     eBPFProcess.on('error', (error) => {
//         console.error(`Spawn error: ${error}`);
//         return res.status(500).send(`Error deploying eBPF program: ${error.message}`);
//     });

//     // eBPFProcess.stdout.on('data', (data) => {
//     //     console.log('message', data.toString());
//     // });

//     // Listen for the 'exit' event to handle the process exit
//     eBPFProcess.on('exit', (code, signal) => {
//         console.log(`eBPF process exited with code ${code} and signal ${signal}`);
//         // Here you can decide whether to proceed with reading and broadcasting logs
//         // based on the exit code or signal
//         readAndBroadcastLogs();
//         res.send("eBPF program and AI model deployed successfully.");
//     });

//     // Optionally, listen for 'data' and 'stderr' events if you need to handle
//     // the process's output in real-time
//     eBPFProcess.stdout.on('data', (data) => {
//         console.log(`stdout: ${data}`);
//         // Handle the stdout data as needed
//     });

//     eBPFProcess.stderr.on('data', (data) => {
//         console.error(`stderr: ${data}`);
//          //res.emit('message', data.toString());
//         // Handle the stderr data as needed
//     });
// });

// // Set up Socket.io connection listener
// io.on("connection", (socket) => {
//   console.log("Socket.io client connected");
//   console.log('A user connected: ' + socket.id);
 
//   const handleFileChange = () => {
//     readAndBroadcastLogs();
//   }; // Set up file watchers

//   const eBPFLogWatcher = chokidar.watch("/home/cheithanya/Desktop/Finalyearproject/eBPF/libbpf-bootstrap/examples/c/process_monitor_log.txt", {
//     persistent: true,
//   });
// //   const modelOutputWatcher = chokidar.watch("/path/to/pid_output.txt", {
// //     persistent: true,
// //   });


//   eBPFLogWatcher.on("change", handleFileChange);
//   //modelOutputWatcher.on("change", handleFileChange);

//   socket.on("disconnect", () => {
//     eBPFLogWatcher.close();
//   //  modelOutputWatcher.close();
//     console.log("Socket.io client disconnected");
//   });
// });

// // Start the server
// server.listen(5000, () => {
//   console.log("Server started on port 5000");
// });

// Import required modules
const fs = require("fs").promises;
const chokidar = require("chokidar");
const express = require("express");
const { spawn } = require("child_process");
const http = require("http");
const { Server } = require("socket.io");
var cors = require('cors')

// Initialize Express app and other configurations
const app = express();
app.use(express.json());
app.use(cors());

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
  },
});

// Function to broadcast data to all connected Socket.io clients
function broadcast(data) {
  io.emit("log-update", data);
}

// Function to read logs from files and broadcast them
async function readAndBroadcastLogs() {
  try {
    const eBPFLogs = await fs.readFile(
      "/home/cheithanya/Desktop/Finalyearproject/eBPF/libbpf-bootstrap/examples/c/process_monitor_log.txt",
      "utf8"
    );
    broadcast({ eBPFLogs });
  } catch (error) {
    console.error("Error reading logs:", error);
  }
}
const validatePath = (path) => {
  return /^\/[a-zA-Z0-9_\/.-]+$/.test(path);
};
// Function to handle deployment requests via Socket.IO
io.on("connection", (socket) => {
  console.log("Socket.io client connected");

  socket.on("deployRequest", async (data) => {
    console.log("Received deploy request:", data); 
    const path = data.path;
    if (!validatePath(path)) {
        return socket.emit("deployError", "Invalid path provided.");
    }

    const command = "bash";
    const args = ["-c", `sudo /home/cheithanya/Desktop/Finalyearproject/eBPF/libbpf-bootstrap/examples/c/monitor -p ${path}`];
    const eBPFProcess = spawn(command, args);
    const modelprocess=spawn(command,["-c","sudo /usr/bin/python3 /home/cheithanya/Desktop/Finalyearproject/model/main.py"])
    

    eBPFProcess.on('error', (error) => {
        console.error(`Spawn error: ${error}`);
        socket.emit("deployError", `Error deploying eBPF program: ${error.message}`);
    });

    eBPFProcess.on('exit', (code, signal) => {
        console.log(`eBPF process exited with code ${code} and signal ${signal}`);
        readAndBroadcastLogs();
        socket.emit("deploySuccess", "eBPF program and AI model deployed successfully.");
    });

    eBPFProcess.stdout.on('data', (data) => {
        console.log(`stdout: ${data}`);
      
    });
    eBPFProcess.stderr.on('data', (data) => {
        // console.error(`stderr: ${data}`);
        socket.emit('message', data.toString());
        
    });
    modelprocess.stderr.on('data',(data)=>{
      socket.emit('model', data.toString());
    })
  });

  // Other Socket.IO event handlers...
});

// Start the server
server.listen(5000, () => {
  console.log("Server started on port 5000");
});
