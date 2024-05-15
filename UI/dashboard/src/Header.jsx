import React from 'react';
import './Header.css';

function Header({ monitoringStatus, ransomwareDetected, systemState, blinking }) {
  const monitoringStatusClass = monitoringStatus === 'On' ? 'status-on' : 'status-off';
  const ransomwareDetectedClass = ransomwareDetected === 'Yes' ? 'status-danger' : 'status-safe';
  const systemStateClass = systemState === 'safe' ? 'status-safe' : 'status-danger';
  const blinkingClass = blinking ? 'blinking' : '';

  return (
    <div className="header">
      <div className='header-title'>
        <div><img style={{height:40,width:140,margin:"10", paddingLeft: '30px', paddingTop: '3px'}} src={"https://upload.wikimedia.org/wikipedia/commons/b/b0/EBPF_logo.png"} alt="" /></div>
        <div className='title'>Multistage Ransomware Detection using eBPF and Honeypot</div>
        <div> <img  style={{height:40,width:210,margin:"10 ", paddingRight: '30px', paddingTop: '3px'}}  src="https://www.cncf.io/wp-content/uploads/2023/04/cncf-main-site-logo.svg"  alt="" /></div>
      </div>
      <div className='break-line'></div>
      <div className='status-bar'>
        <div className={`ransomware-monitoring ${monitoringStatusClass} ${blinkingClass}`}>Ransomware Monitoring: {monitoringStatus}</div>
        <div className={`ransomware-detected ${ransomwareDetectedClass}`}>Ransomware Detected: {ransomwareDetected}</div>
        <div className={`system-state ${systemStateClass}`}>System State: {systemState}</div>
      </div>
    </div>
  );
}

export default Header;
