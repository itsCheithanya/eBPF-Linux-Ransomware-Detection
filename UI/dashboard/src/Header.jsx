import React from 'react';
import './Header.css'

function Header(){
    return (
        <div className="header">
            <div className='header-title'>
                <div className='title'>Multistage Ransomware Detection using eBPF and Honeypot</div>
            </div>
            <div className='break-line'></div>
            <div className='status-bar'>
            </div>
        </div>
    )
}

export default Header