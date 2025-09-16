import React, { useState } from 'react';
import PacketInspector from './PacketInspector.jsx';

const PacketInspectorTest = () => {
    const [showInspector, setShowInspector] = useState(false);
    
    const testConnection = {
        src_ip: "192.168.1.157",
        dst_ip: "224.0.0.251", 
        src_port: 5353,
        dst_port: 5353,
        protocol: "UDP",
        timestamp: Date.now() / 1000
    };
    
    return (
        <div style={{ padding: '20px' }}>
            <h1>PacketInspector Test Page</h1>
            <button 
                onClick={() => setShowInspector(!showInspector)}
                style={{ 
                    padding: '10px 20px', 
                    fontSize: '16px',
                    backgroundColor: '#007bff',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: 'pointer'
                }}
            >
                {showInspector ? 'Hide' : 'Show'} Packet Inspector
            </button>
            
            {showInspector && (
                <div style={{ 
                    position: 'fixed',
                    top: 0,
                    left: 0,
                    right: 0,
                    bottom: 0,
                    backgroundColor: 'rgba(0,0,0,0.5)',
                    zIndex: 1000,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                }}>
                    <div style={{
                        width: '90%',
                        height: '90%',
                        backgroundColor: 'white',
                        borderRadius: '8px'
                    }}>
                        <PacketInspector 
                            selectedConnection={testConnection}
                            onClose={() => setShowInspector(false)}
                        />
                    </div>
                </div>
            )}
        </div>
    );
};

export default PacketInspectorTest;
