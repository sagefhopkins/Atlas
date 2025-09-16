import React, { useState, useEffect } from 'react';
import axios from 'axios';
import styles from './PacketInspector.module.css';

const PacketInspector = ({ selectedConnection, onClose }) => {
    const [packets, setPackets] = useState([]);
    const [selectedPacket, setSelectedPacket] = useState(null);
    const [packetDetails, setPacketDetails] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [viewMode, setViewMode] = useState('list');

    useEffect(() => {
        if (selectedConnection) {
            loadPacketsForConnection();
        } else {
            loadRecentPackets();
        }
    }, [selectedConnection]);

    const loadPacketsForConnection = async () => {
        if (!selectedConnection) return;
        
        try {
            setIsLoading(true);
            setError('');
            
            const { src_ip, dst_ip, src_port, dst_port, protocol } = selectedConnection;
            
            const params = { limit: 100 };
            if (src_port !== null && src_port !== undefined) {
                params.src_port = src_port;
            }
            if (dst_port !== null && dst_port !== undefined) {
                params.dst_port = dst_port;
            }
            if (protocol !== null && protocol !== undefined) {
                params.protocol = protocol;
            }
            
            const response = await axios.get(
                `http://localhost:8000/packets/connection/${src_ip}/${dst_ip}`,
                { params }
            );
            
            const packets = response.data.packets || [];
            
            if (packets.length === 0) {
                const broadParams = { limit: 50 };
                if (protocol !== null && protocol !== undefined) {
                    broadParams.protocol = protocol;
                }
                
                const broadResponse = await axios.get(
                    `http://localhost:8000/packets/connection/${src_ip}/${dst_ip}`,
                    { params: broadParams }
                );
                
                const broadPackets = broadResponse.data.packets || [];
                
                if (broadPackets.length === 0) {
                    const reverseParams = { limit: 50 };
                    if (protocol !== null && protocol !== undefined) {
                        reverseParams.protocol = protocol;
                    }
                    
                    const reverseResponse = await axios.get(
                        `http://localhost:8000/packets/connection/${dst_ip}/${src_ip}`,
                        { params: reverseParams }
                    );
                    
                    const reversePackets = reverseResponse.data.packets || [];
                    
                    if (reversePackets.length === 0) {
                        const recentResponse = await axios.get('http://localhost:8000/packets/recent', {
                            params: { limit: 50 }
                        });
                        setPackets(recentResponse.data.packets || []);
                        setError('No packets found for this specific connection. Showing recent packets instead.');
                    } else {
                        setPackets(reversePackets);
                        setError('No packets found in original direction. Showing reverse direction packets.');
                    }
                } else {
                    setPackets(broadPackets);
                    setError('No packets found with exact ports. Showing packets for same IPs and protocol.');
                }
            } else {
                setPackets(packets);
            }
        } catch (error) {
            console.error('Failed to load connection packets:', error);
            setError('Failed to load packets for this connection');
        } finally {
            setIsLoading(false);
        }
    };

    const loadRecentPackets = async () => {
        try {
            setIsLoading(true);
            setError('');
            
            const response = await axios.get('http://localhost:8000/packets/recent', {
                params: { limit: 100 }
            });
            
            setPackets(response.data.packets || []);
        } catch (error) {
            console.error('Failed to load recent packets:', error);
            setError('Failed to load recent packets');
        } finally {
            setIsLoading(false);
        }
    };

    const loadPacketDetails = async (packetId) => {
        try {
            const response = await axios.get(`http://localhost:8000/packets/${packetId}`);
            return response.data;
        } catch (error) {
            console.error('Failed to load packet details:', error);
            return null;
        }
    };

    const handlePacketClick = async (packet) => {
        setSelectedPacket(packet);
        const details = await loadPacketDetails(packet.packet_id);
        setPacketDetails(details);
        setViewMode('details');
    };

    const handleBackToList = () => {
        setViewMode('list');
        setSelectedPacket(null);
        setPacketDetails(null);
    };

    const exportPacket = async (format) => {
        if (!selectedPacket) return;
        
        try {
            const response = await axios.get(
                `http://localhost:8000/packets/${selectedPacket.packet_id}/export`,
                { params: { format } }
            );
            
            const data = JSON.stringify(response.data, null, 2);
            const blob = new Blob([data], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `packet_${selectedPacket.packet_id}.${format}`;
            link.click();
            URL.revokeObjectURL(url);
        } catch (error) {
            console.error('Failed to export packet:', error);
            setError('Failed to export packet');
        }
    };

    const formatTimestamp = (timestamp) => {
        return new Date(timestamp * 1000).toLocaleString();
    };

    const getPacketTypeIcon = (packetType) => {
        const icons = {
            'TCP': '🔗',
            'UDP': '📡',
            'ICMP': '🏓',
            'DNS': '🔍',
            'HTTP_REQUEST': '📤',
            'HTTP_RESPONSE': '📥',
            'ARP': '📍',
            'OTHER': '❓'
        };
        return icons[packetType] || '📦';
    };

    const getRiskLevelColor = (riskLevel) => {
        switch (riskLevel) {
            case 'low': return '#4ade80';
            case 'medium': return '#fbbf24';
            case 'high': return '#ef4444';
            default: return '#6b7280';
        }
    };


    return (
        <div className={styles.packetInspector}>
            <div>
                <div className={styles.header}>
                    <h2>Packet Inspector</h2>
                    <button className={styles.closeButton} onClick={onClose}>✕</button>
                </div>

                <div className={styles.toolbar}>
                    <button 
                        className={styles.refreshButton}
                        onClick={selectedConnection ? loadPacketsForConnection : loadRecentPackets}
                    >
                        🔄 Refresh
                    </button>
                    {selectedConnection && (
                        <div className={styles.connectionInfo}>
                            <span>📡 {selectedConnection.src_ip}{selectedConnection.src_port ? `:${selectedConnection.src_port}` : ''} → {selectedConnection.dst_ip}{selectedConnection.dst_port ? `:${selectedConnection.dst_port}` : ''} ({selectedConnection.protocol || 'Any'})</span>
                        </div>
                    )}
                </div>

                {error && (
                    <div className={styles.error}>
                        {error}
                    </div>
                )}

                {isLoading && (
                    <div className={styles.loading}>
                        Loading packets...
                    </div>
                )}

                <div className={styles.content}>
                    {viewMode === 'list' && (
                        <div className={styles.packetList}>
                            {packets.map((packet, index) => {
                                const analysis = packet.analysis || {};
                                const security = analysis.security || {};
                                
                                return (
                                    <div 
                                        key={packet.packet_id || index}
                                        className={styles.packetRow}
                                        onClick={() => handlePacketClick(packet)}
                                    >
                                        <div className={styles.packetIcon}>
                                            {getPacketTypeIcon(analysis.packet_type)}
                                        </div>
                                        <div className={styles.packetSummary}>
                                            <div className={styles.packetType}>
                                                {analysis.packet_type || 'Unknown'}
                                            </div>
                                            <div className={styles.packetFlow}>
                                                {analysis.src_ip || 'N/A'}{analysis.src_port ? `:${analysis.src_port}` : ''} → {analysis.dst_ip || 'N/A'}{analysis.dst_port ? `:${analysis.dst_port}` : ''}
                                            </div>
                                            <div className={styles.packetMeta}>
                                                <span className={styles.packetSize}>{analysis.size || 0}B</span>
                                                <span className={styles.packetTime}>{formatTimestamp(packet.timestamp || analysis.timestamp)}</span>
                                            </div>
                                        </div>
                                        <div className={styles.packetRisk}>
                                            <span 
                                                className={styles.riskBadge}
                                                style={{ backgroundColor: getRiskLevelColor(security.risk_level) }}
                                            >
                                                {security.risk_level || 'low'}
                                            </span>
                                        </div>
                                    </div>
                                );
                            })}
                            
                            {packets.length === 0 && !isLoading && (
                                <div className={styles.noPackets}>
                                    No packets found
                                </div>
                            )}
                        </div>
                    )}

                    {viewMode === 'details' && packetDetails && (
                        <div className={styles.packetDetails}>
                            <div className={styles.detailsHeader}>
                                <button className={styles.backButton} onClick={handleBackToList}>
                                    ← Back to List
                                </button>
                                <h3>Packet {packetDetails.packet_id}</h3>
                                <div className={styles.exportButtons}>
                                    <button className={styles.exportButton} onClick={() => exportPacket('json')}>
                                        📄 JSON
                                    </button>
                                    <button className={styles.exportButton} onClick={() => exportPacket('hex')}>
                                        🔢 Hex
                                    </button>
                                </div>
                            </div>

                            <div className={styles.detailsContent}>
                                <div className={styles.section}>
                                    <h4>📊 Summary</h4>
                                    <div className={styles.summaryGrid}>
                                        <div className={styles.summaryItem}>
                                            <label>Summary:</label>
                                            <span>{packetDetails.analysis?.summary || 'N/A'}</span>
                                        </div>
                                        <div className={styles.summaryItem}>
                                            <label>Type:</label>
                                            <span>{packetDetails.analysis?.packet_type || 'Unknown'}</span>
                                        </div>
                                        <div className={styles.summaryItem}>
                                            <label>Size:</label>
                                            <span>{packetDetails.analysis?.size || 0} bytes</span>
                                        </div>
                                        <div className={styles.summaryItem}>
                                            <label>Protocol:</label>
                                            <span>{packetDetails.analysis?.protocol_name || packetDetails.analysis?.protocol || 'Unknown'}</span>
                                        </div>
                                        <div className={styles.summaryItem}>
                                            <label>Service:</label>
                                            <span>{packetDetails.analysis?.service || 'Unknown'}</span>
                                        </div>
                                    </div>
                                </div>

                                {packetDetails.analysis?.security && (
                                    <div className={styles.section}>
                                        <h4>🔒 Security Analysis</h4>
                                        <div className={styles.securityGrid}>
                                            <div className={styles.securityItem}>
                                                <label>Risk Level:</label>
                                                <span 
                                                    className={styles.riskBadge}
                                                    style={{ backgroundColor: getRiskLevelColor(packetDetails.analysis.security.risk_level) }}
                                                >
                                                    {packetDetails.analysis.security.risk_level || 'low'}
                                                </span>
                                            </div>
                                            <div className={styles.securityItem}>
                                                <label>Encrypted:</label>
                                                <span>{packetDetails.analysis.security.is_encrypted ? '✅ Yes' : '❌ No'}</span>
                                            </div>
                                            <div className={styles.securityItem}>
                                                <label>Suspicious:</label>
                                                <span>{packetDetails.analysis.security.is_suspicious ? '⚠️ Yes' : '✅ No'}</span>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {packetDetails.headers && Object.keys(packetDetails.headers).length > 0 && (
                                    <div className={styles.section}>
                                        <h4>📋 Protocol Headers</h4>
                                        {Object.entries(packetDetails.headers).map(([protocol, header]) => (
                                            <div key={protocol} className={styles.headerSection}>
                                                <h5>{protocol.toUpperCase()} Header</h5>
                                                <div className={styles.headerContent}>
                                                    <pre className={styles.headerData}>
                                                        {typeof header === 'object' ? JSON.stringify(header, null, 2) : header}
                                                    </pre>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default PacketInspector;
