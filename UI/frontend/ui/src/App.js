import React, { useState, useEffect } from "react";
import axios from "axios";
import { Layout, Row, Col, Card, Typography, Button, Spin, Input } from "antd";
import { io } from 'socket.io-client';
import App1 from "./Honeypot";

const { Content } = Layout;
const { TextArea } = Input;
const { Title, Paragraph } = Typography;

function App() {
  const [dataPath, setDataPath] = useState("");
  const [eBPFLogs, setEBPFLogs] = useState("Awaiting logs...");
  const [modelOutput, setModelOutput] = useState("Awaiting model output...");
  const [honeypotOutput, setHoneypotOutput] = useState("Awaiting honeypot output...");
  const [loading, setLoading] = useState(false);
  const [socket, setSocket] = useState(null);
  const [deployed, setDeployed] = useState(false);
  const [ebpfdata,setEbpfdata]=useState("");
  const [modeldata,setModeldata]=useState("");

  useEffect(() => {
    const newSocket = io('http://localhost:5000');
    setSocket(newSocket);
    newSocket.on("message", (event) => {
      setEbpfdata((ebpfdata)=>[...ebpfdata,event]);
    });
    newSocket.on("model", (event) => {
      setModeldata(...modeldata,event);
    });
    newSocket.on("open", () => {
      console.log("Connected to WebSocket");
    });
    newSocket.on("close", () => {
      console.log("Disconnected from WebSocket");
    });
    newSocket.on("deploySuccess", () => {
      setDeployed(true);
    });
    newSocket.on("deployError", (errorMessage) => {
      console.error(errorMessage);
      // Handle error appropriately, e.g., show an error message to the user
    });

    return () => newSocket.disconnect();
  }, []);

  const deployEBPFAndRunModel = () => {
    setLoading(true);
    if (!socket ||!dataPath) {
      console.error("Socket not connected or no path provided.");
      setLoading(false);
      return;
    }
    socket.emit("deployRequest", { path: dataPath });
  };

  return (
    <Layout>
      <Content style={{ padding: "20px" }}>
        <Title>eBPF based Linux Ransomware Detection using AI</Title>
        <App1/>
        <Row gutter={16}>
          <Col span={12}>
            <Card title="Stage 1: eBPF Logs" bordered={false}>
              <Paragraph>Enter the path to the data to be monitored:</Paragraph>
              <Input
                placeholder="/path/to/data"
                value={dataPath}
                onChange={(e) => setDataPath(e.target.value)}
                style={{ marginBottom: "10px" }}
              />
              <Button
                type="primary"
                onClick={deployEBPFAndRunModel}
                disabled={loading}
              >
                Deploy eBPF Program & Run Analysis
              </Button>
              {loading && <Spin />}
              <div
                style={{
                  background: "#000",
                  color: "#fff",
                  fontFamily: "monospace",
                  marginTop: "20px",
                  padding: "10px",
                  overflow: "auto",
                  whiteSpace: "pre-wrap",
                  height: "400px",
                }}
              >
                {ebpfdata}
              </div>
            </Card>
          </Col>
          <Col span={12}>
            <Card title="Stage 2: Model Output" bordered={false}>
               <div
                style={{
                  background: "#000",
                  color: "#fff",
                  fontFamily: "monospace",
                  marginTop: "20px",
                  padding: "10px",
                  overflow: "auto",
                  whiteSpace: "pre-wrap",
                  height: "400px",
                }}
              >
                {modeldata}
              </div>
            </Card>
          </Col>
       
        </Row>
      </Content>
    </Layout>
  );
}

export default App;
