import './Body.css';
import React from 'react';
import { useEffect} from 'react';
import { io } from 'socket.io-client';
import styles from './Body.css';
import { useRef, useState } from 'react';
import CSection from './cSection';

function Body(){ 
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
        <div className='content-body'>
            <div className='cheithanya-section'>
                <CSection />
            </div>

            <div className='bhuvan-section'>
                <div className='monitoringSection'>
                    <h1 className='diff-header'>Global Monitoring</h1>
                        <div className='buttonWrapper'>
                            <button className={isGlobalMonitoringActive ? 'buttonDisabled' : 'button'} onClick={handleRunGlobalMonitoring} disabled={isGlobalMonitoringActive}>Start Global Monitoring</button>
                            <button className={!isGlobalMonitoringActive ? 'buttonDisabled' : 'button'} onClick={handleStopGlobalMonitoring} disabled={!isGlobalMonitoringActive}>Stop Global Monitoring</button>
                        </div>
                        <div className='logs'>
                            <h2 style={{backgroundColor: '#20232a'}}>Logs from Global Monitoring</h2>
                            <div className='scrollableWin'>
                                {messages.map((msg, index) => (
                                <p className='logMessage' key={index} ref={index === messages.length - 1 ? lastGlobalMessageRef : null}>{msg}</p>
                                ))}
                            </div>
                        </div>
                </div>


                <div className='monitoringSection'>
                    <h1 className='diff-header'>Honey Pot Monitoring</h1>
                    <div className='buttonWrapper'>
                        <button className={isHoneyPotActive ? 'buttonDisabled' : 'button'} onClick={handleRunHoneyPot} disabled={isHoneyPotActive}>Start Honey Pot Monitoring</button>
                        <button className={!isHoneyPotActive ? 'buttonDisabled' : 'button'} onClick={handleStopHoneyPot} disabled={!isHoneyPotActive}>Stop Honey Pot Monitoring</button>
                    </div>        
                    <div className='logs'>
                        <h2 >Logs from Honey Pot Monitoring</h2>
                        <div className='scrollableWin'>
                            {honeyPotMessages.map((msg, index) => (
                            <p className='logMessage' key={index} ref={index === honeyPotMessages.length - 1 ? lastHoneyPotMessageRef : null}>{msg}</p>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

        </div>
    );
}

export default Body