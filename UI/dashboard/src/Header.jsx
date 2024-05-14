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
        <div><img style={{height:30,width:95,margin:"10", paddingLeft: '30px', paddingTop: '3px'}} src={"https://ebpf.foundation/wp-content/uploads/sites/9/2023/02/ebpf_logo_monochrome_on_dark-300x106.png"} alt="" /></div>
        <div className='title'>Multistage Ransomware Detection using eBPF and Honeypot</div>
        <div> <img  style={{height:25,width:140,margin:"10 ", paddingRight: '30px', paddingTop: '3px'}}  src="https://nats.io/img/logos/cncf-white.png" alt="" /></div>
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
