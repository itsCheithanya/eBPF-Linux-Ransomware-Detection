import axios from "axios";
import { Layout, Row, Col, Card, Typography, Button, Spin, Input } from "antd";
import { io } from 'socket.io-client';
import React, { useState, useEffect } from "react";

const { Content } = Layout;
const { TextArea } = Input;
const { Title, Paragraph } = Typography;

function CSection() {
  const [dataPath, setDataPath] = useState("");
  const [eBPFLogs, setEBPFLogs] = useState("Awaiting logs...");
  const [modelOutput, setModelOutput] = useState("Awaiting model output...");
  const [honeypotOutput, setHoneypotOutput] = useState("Awaiting honeypot output...");
  const [loading, setLoading] = useState(false);
  const [socket, setSocket] = useState(null);
  const [deployed, setDeployed] = useState(false);
  const [ebpfdata, setEbpfdata] = useState("");
  const [modeldata, setModeldata] = useState("");

  useEffect(() => {
    const newSocket = io('http://localhost:5000');
    setSocket(newSocket);
    newSocket.on("message", (event) => {
      setEbpfdata((ebpfdata) => [...ebpfdata, event]);
    });
    newSocket.on("model", (event) => {
      if (event.trim() === "600 Alert") {
        
      }
      setModeldata((modeldata)=>[...modeldata, event]);
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
    if (!socket || !dataPath) {
      console.error("Socket not connected or no path provided.");
      setLoading(false);
      return;
    }
    // setIsMonitoringActive(true);
    socket.emit("deployRequest", { path: dataPath });
  };

  return (
    <Layout style={{ background: '#20232a', borderRadius: '15px' }}>
      <Content style={{ padding: "20px" }}>
        <Row gutter={16}>
          <Col span={12}>
            <Card bordered={false} style={{ background: '#20232a' }}>
              <div style={{ color: '#61dafb', fontSize: '18px', fontWeight: 'bolder' }}>Stage 1: eBPF Logs</div>
              <Paragraph style={{ color: 'aquamarine' }}>Enter the path to the data to be monitored:</Paragraph>
              <Input
                placeholder="/path/to/data"
                value={dataPath}
                onChange={(e) => setDataPath(e.target.value)}
                style={{ marginBottom: "10px" }}
              />
              <Button
                type="primary"
                onClick={deployEBPFAndRunModel}
                disabled={loading} style={{ background: '#4fa1c7' }}
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
                  borderRadius: '10px'
                }}
              >
                {ebpfdata}
              </div>
            </Card>
          </Col>
          <Col span={12}>
            <Card bordered={false} style={{ background: '#20232a' }}>
              <div style={{ color: '#61dafb', fontSize: '18px', fontWeight: 'bolder' }}>AI Model Output</div>
              <div
                style={{
                  background: "#000",
                  color: "#fff",
                  fontFamily: "monospace",
                  marginTop: "20px",
                  padding: "10px",
                  overflow: 'auto',
                  whiteSpace: "pre-wrap",
                  height: "400px",
                  borderRadius: '10px'
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

export default CSection