import React, { useEffect, useRef, useState } from 'react';
import { io } from 'socket.io-client';
import styles from './App.module.css';

function App1() {
  const [messages, setMessages] = useState([]);
  const [honeyPotMessages, setHoneyPotMessages] = useState([]);
  const [socket, setSocket] = useState(null);
  const [isGlobalMonitoringActive, setIsGlobalMonitoringActive] = useState(false);
  const [isHoneyPotActive, setIsHoneyPotActive] = useState(false);
  const [showPopup, setShowPopup] = useState(false);
  const lastGlobalMessageRef = useRef(null);
  const lastHoneyPotMessageRef = useRef(null);

  useEffect(() => {
    const newSocket = io('http://localhost:5000');
    setSocket(newSocket);

    newSocket.on('message', message => {
      console.log('Received Global Monitoring message:', message);
      setMessages(prevMessages => [...prevMessages, message]);
    });

    newSocket.on('process-id', pid => {
      setMessages(prevMessages => [...prevMessages, `Global Monitoring Process ID: ${pid}`]);
    });

    newSocket.on('honeypot-message', message => {
      console.log('Received Honey Pot message:', message);
      if (message.trim() === "600 Alert") {
        setShowPopup(true);
      }
      setHoneyPotMessages(prevMessages => [...prevMessages, message]);
    });

    newSocket.on('honeypot-process-id', pid => {
      setHoneyPotMessages(prevMessages => [...prevMessages, `Honey Pot Process ID: ${pid}`]);
    });

    return () => newSocket.disconnect();
  }, []);

  useEffect(() => {
    if (lastGlobalMessageRef.current) {
      lastGlobalMessageRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  useEffect(() => {
    if (lastHoneyPotMessageRef.current) {
      lastHoneyPotMessageRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [honeyPotMessages]);

  const handleRunGlobalMonitoring = () => {
    socket.emit('run-script');
    setIsGlobalMonitoringActive(true);
  };

  const handleStopGlobalMonitoring = () => {
    socket.emit('stop-script');
    setIsGlobalMonitoringActive(false);
  };

  const handleRunHoneyPot = () => {
    socket.emit('run-honeypot');
    setIsHoneyPotActive(true);
  };

  const handleStopHoneyPot = () => {
    socket.emit('stop-honeypot');
    setIsHoneyPotActive(false);
  };

  const handleClosePopup = () => {
    setShowPopup(false);
  };

  return (
    <div className={styles.container}>
      {showPopup && (
        <div className={styles.popup}>
          <h2 style={{ color: 'red', border: '2px solid red', padding: '10px' }}>Ransomware Detected</h2>
          <button onClick={handleClosePopup}>Close</button>
        </div>
      )}

      <div className={styles.monitoringSection}>
        <h1 className={styles.header}>Global Monitoring</h1>
        <div className={styles.buttonWrapper}>
          <button className={isGlobalMonitoringActive ? styles.buttonDisabled : styles.button} onClick={handleRunGlobalMonitoring} disabled={isGlobalMonitoringActive}>Start Global Monitoring</button>
          <button className={!isGlobalMonitoringActive ? styles.buttonDisabled : styles.button} onClick={handleStopGlobalMonitoring} disabled={!isGlobalMonitoringActive}>Stop Global Monitoring</button>
        </div>
        <div className={styles.logs}>
          <h2 style={{backgroundColor: '#20232a'}}>Logs from Global Monitoring</h2>
          <div className={styles.scrollableWin}>
            {messages.map((msg, index) => (
              <p className={styles.logMessage} key={index} ref={index === messages.length - 1 ? lastGlobalMessageRef : null}>{msg}</p>
            ))}
          </div>
        </div>
      </div>

      <div className={styles.monitoringSection}>
        <h1 className={styles.header}>Honey Pot Monitoring</h1>
        <div className={styles.buttonWrapper}>
          <button className={isHoneyPotActive ? styles.buttonDisabled : styles.button} onClick={handleRunHoneyPot} disabled={isHoneyPotActive}>Start Honey Pot Monitoring</button>
          <button className={!isHoneyPotActive ? styles.buttonDisabled : styles.button} onClick={handleStopHoneyPot} disabled={!isHoneyPotActive}>Stop Honey Pot Monitoring</button>
        </div>        
        <div className={styles.logs}>
          <h2 style={{backgroundColor: '#20232a'}}>Logs from Honey Pot Monitoring</h2>
          <div className={styles.scrollableWin}>

            {honeyPotMessages.map((msg, index) => (
              <p className={styles.logMessage} key={index} ref={index === honeyPotMessages.length - 1 ? lastHoneyPotMessageRef : null}>{msg}</p>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App1;