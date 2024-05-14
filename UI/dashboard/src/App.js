import './App.css';
import Header from './Header';
import Body from './Body';
import { useState, useCallback } from 'react';

function App() {
  const [monitoringStatus, setMonitoringStatus] = useState('Off');
  const [ransomwareDetected, setRansomwareDetected] = useState('No');
  const [systemState, setSystemState] = useState('safe');
  const [blinking, setBlinking] = useState(false);

  const handleMonitoringStatusChange = useCallback((status) => {
    setMonitoringStatus(status);
  }, []);

  const handleBlinkingChange = useCallback((isBlinking) => {
    setBlinking(isBlinking);
  }, []);

  const handleRansomwareAlert = useCallback(() => {
    setRansomwareDetected('Yes');
    setSystemState('Not Safe');
  }, []);

  return (
    <div className="App">
      <Header 
        monitoringStatus={monitoringStatus} 
        ransomwareDetected={ransomwareDetected} 
        systemState={systemState}
        blinking={blinking}
      />
      <Body 
        setMonitoringStatus={handleMonitoringStatusChange} 
        setRansomwareDetected={setRansomwareDetected} 
        setSystemState={setSystemState} 
        setBlinking={handleBlinkingChange}
        handleRansomwareAlert={handleRansomwareAlert}
      />
    </div>
  );
}

export default App;
