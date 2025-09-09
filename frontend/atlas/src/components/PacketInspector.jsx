import React, { useState, useEffect } from 'react';
import axios from 'axios';
import styles from './PacketInspector.module.css';

const PacketInspector = ({ selectedConnection, onClose }) => {
    const [packets, setPackets] = useState([]);
    const [selectedPacket, setSelectedPacket] = useState(null);
    const [packetDetails, setPacketDetails] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [activeTab, setActiveTab] = useState('list');

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
            const response = await axios.get(
                `http://localhost:8000/packets/connection/${src_ip}/${dst_ip}`,
                {
                    params: {
                        src_port,
                        dst_port,
                        protocol,
                        limit: 100
                    }
                }
            );
            
            setPackets(response.data.packets || []);
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
            setIsLoading(true);
            setError('');
            
            const response = await axios.get(`http://localhost:8000/packets/${packetId}`);
            setPacketDetails(response.data);
            setActiveTab('details');
        } catch (error) {
            console.error('Failed to load packet details:', error);
            setError('Failed to load packet details');
        } finally {
            setIsLoading(false);
        }
    };

    const handlePacketSelect = (packet) => {
        setSelectedPacket(packet);
        loadPacketDetails(packet.packet_id);
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
            <div className={styles.header}>
                <h2>Packet Inspector</h2>
                <button className={styles.closeButton} onClick={onClose}>✕</button>
            </div>

            <div className={styles.tabs}>
                <button 
                    className={`${styles.tab} ${activeTab === 'list' ? styles.tabActive : ''}`}
                    onClick={() => setActiveTab('list')}
                >
                    📋 Packet List
                </button>
                <button 
                    className={`${styles.tab} ${activeTab === 'details' ? styles.tabActive : ''}`}
                    onClick={() => setActiveTab('details')}
                    disabled={!selectedPacket}
                >
                    🔍 Details
                </button>
                <button 
                    className={`${styles.tab} ${activeTab === 'hexdump' ? styles.tabActive : ''}`}
                    onClick={() => setActiveTab('hexdump')}
                    disabled={!packetDetails}
                >
                    🔢 Hex Dump
                </button>
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

            {activeTab === 'list' && (
                <div className={styles.packetList}>
                    <div className={styles.listHeader}>
                        <div className={styles.listControls}>
                            <button 
                                className={styles.refreshButton}
                                onClick={selectedConnection ? loadPacketsForConnection : loadRecentPackets}
                            >
                                🔄 Refresh
                            </button>
                            {selectedConnection && (
                                <div className={styles.connectionInfo}>
                                    <span>📡 {selectedConnection.src_ip}:{selectedConnection.src_port} → {selectedConnection.dst_ip}:{selectedConnection.dst_port} ({selectedConnection.protocol})</span>
                                </div>
                            )}
                        </div>
                    </div>

                    <div className={styles.packetsTable}>
                        <div className={styles.tableHeader}>
                            <div>Type</div>
                            <div>Source</div>
                            <div>Destination</div>
                            <div>Protocol</div>
                            <div>Size</div>
                            <div>Time</div>
                            <div>Risk</div>
                        </div>
                        
                        {packets.map((packet, index) => {
                            const analysis = packet.analysis || {};
                            const security = analysis.security || {};
                            const routing = analysis.routing || {};
                            
                            return (
                                <div 
                                    key={packet.packet_id || index}
                                    className={`${styles.packetRow} ${selectedPacket?.packet_id === packet.packet_id ? styles.selectedRow : ''}`}
                                    onClick={() => handlePacketSelect(packet)}
                                >
                                    <div className={styles.packetType}>
                                        <span className={styles.typeIcon}>
                                            {getPacketTypeIcon(analysis.packet_type)}
                                        </span>
                                        <span>{analysis.packet_type || 'Unknown'}</span>
                                    </div>
                                    <div className={styles.sourceInfo}>
                                        <div>{analysis.src_ip || 'N/A'}</div>
                                        {analysis.src_port && <div className={styles.port}>:{analysis.src_port}</div>}
                                    </div>
                                    <div className={styles.destInfo}>
                                        <div>{analysis.dst_ip || 'N/A'}</div>
                                        {analysis.dst_port && <div className={styles.port}>:{analysis.dst_port}</div>}
                                    </div>
                                    <div className={styles.protocol}>
                                        {analysis.protocol_name || analysis.protocol || 'Unknown'}
                                    </div>
                                    <div className={styles.size}>
                                        {analysis.size || 0} bytes
                                    </div>
                                    <div className={styles.timestamp}>
                                        {formatTimestamp(packet.timestamp || analysis.timestamp)}
                                    </div>
                                    <div className={styles.riskLevel}>
                                        <span 
                                            className={styles.riskIndicator}
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
                </div>
            )}

            {activeTab === 'details' && packetDetails && (
                <div className={styles.packetDetails}>
                    <div className={styles.detailsHeader}>
                        <h3>Packet Details: {packetDetails.packet_id}</h3>
                        <div className={styles.exportButtons}>
                            <button 
                                className={styles.exportButton}
                                onClick={() => exportPacket('json')}
                            >
                                📄 JSON
                            </button>
                            <button 
                                className={styles.exportButton}
                                onClick={() => exportPacket('hex')}
                            >
                                🔢 Hex
                            </button>
                            <button 
                                className={styles.exportButton}
                                onClick={() => exportPacket('hexdump')}
                            >
                                📋 Hex Dump
                            </button>
                        </div>
                    </div>

                    <div className={styles.detailsContent}>
                        {/* Summary Section */}
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
                                    <label>Service:</label>
                                    <span>{packetDetails.analysis?.service || 'Unknown'}</span>
                                </div>
                            </div>
                        </div>

                        {packetDetails.analysis?.routing && (
                            <div className={styles.section}>
                                <h4>🌐 Routing Information</h4>
                                <div className={styles.routingGrid}>
                                    <div className={styles.routingItem}>
                                        <label>Direction:</label>
                                        <span className={styles.direction}>
                                            {packetDetails.analysis.routing.direction || 'Unknown'}
                                        </span>
                                    </div>
                                    <div className={styles.routingItem}>
                                        <label>Traffic Type:</label>
                                        <span>{packetDetails.analysis.routing.traffic_type || 'Unknown'}</span>
                                    </div>
                                    <div className={styles.routingItem}>
                                        <label>TTL:</label>
                                        <span>{packetDetails.analysis.routing.ttl || 'N/A'}</span>
                                    </div>
                                    <div className={styles.routingItem}>
                                        <label>Estimated Hops:</label>
                                        <span>{packetDetails.analysis.routing.hop_count_estimate || 'N/A'}</span>
                                    </div>
                                </div>
                            </div>
                        )}

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
                                
                                {packetDetails.analysis.security.warnings?.length > 0 && (
                                    <div className={styles.warningsSection}>
                                        <label>⚠️ Warnings:</label>
                                        <ul className={styles.warningsList}>
                                            {packetDetails.analysis.security.warnings.map((warning, index) => (
                                                <li key={index} className={styles.warningItem}>
                                                    {warning}
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                )}
                            </div>
                        )}

                        {packetDetails.headers && Object.keys(packetDetails.headers).length > 0 && (
                            <div className={styles.section}>
                                <h4>📋 Protocol Headers</h4>
                                {Object.entries(packetDetails.headers).map(([protocol, header]) => (
                                    <div key={protocol} className={styles.headerSection}>
                                        <h5>{protocol.toUpperCase()} Header</h5>
                                        <div className={styles.headerContent}>
                                            {typeof header === 'object' ? (
                                                <pre className={styles.jsonDisplay}>
                                                    {JSON.stringify(header, null, 2)}
                                                </pre>
                                            ) : (
                                                <span>{header}</span>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}

                        {(packetDetails.analysis?.dns_info || packetDetails.analysis?.http_info) && (
                            <div className={styles.section}>
                                <h4>🔧 Application Layer</h4>
                                
                                {packetDetails.analysis.dns_info && (
                                    <div className={styles.appLayerSection}>
                                        <h5>DNS Information</h5>
                                        <div className={styles.dnsInfo}>
                                            <div className={styles.dnsItem}>
                                                <label>Type:</label>
                                                <span>{packetDetails.analysis.dns_info.is_response ? 'Response' : 'Query'}</span>
                                            </div>
                                            <div className={styles.dnsItem}>
                                                <label>ID:</label>
                                                <span>{packetDetails.analysis.dns_info.id}</span>
                                            </div>
                                            
                                            {packetDetails.analysis.dns_info.queries?.length > 0 && (
                                                <div className={styles.dnsQueries}>
                                                    <label>Queries:</label>
                                                    <ul>
                                                        {packetDetails.analysis.dns_info.queries.map((query, index) => (
                                                            <li key={index}>
                                                                {query.name} ({query.type_name})
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}
                                            
                                            {packetDetails.analysis.dns_info.answers?.length > 0 && (
                                                <div className={styles.dnsAnswers}>
                                                    <label>Answers:</label>
                                                    <ul>
                                                        {packetDetails.analysis.dns_info.answers.map((answer, index) => (
                                                            <li key={index}>
                                                                {answer.name} → {answer.data} (TTL: {answer.ttl})
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                )}

                                {packetDetails.analysis.http_info && (
                                    <div className={styles.appLayerSection}>
                                        <h5>HTTP Information</h5>
                                        <div className={styles.httpInfo}>
                                            <div className={styles.httpItem}>
                                                <label>Type:</label>
                                                <span>{packetDetails.analysis.http_info.type}</span>
                                            </div>
                                            
                                            {packetDetails.analysis.http_info.method && (
                                                <div className={styles.httpItem}>
                                                    <label>Method:</label>
                                                    <span>{packetDetails.analysis.http_info.method}</span>
                                                </div>
                                            )}
                                            
                                            {packetDetails.analysis.http_info.path && (
                                                <div className={styles.httpItem}>
                                                    <label>Path:</label>
                                                    <span>{packetDetails.analysis.http_info.path}</span>
                                                </div>
                                            )}
                                            
                                            {packetDetails.analysis.http_info.status_code && (
                                                <div className={styles.httpItem}>
                                                    <label>Status:</label>
                                                    <span>{packetDetails.analysis.http_info.status_code} {packetDetails.analysis.http_info.reason_phrase}</span>
                                                </div>
                                            )}
                                            
                                            {packetDetails.analysis.http_info.host && (
                                                <div className={styles.httpItem}>
                                                    <label>Host:</label>
                                                    <span>{packetDetails.analysis.http_info.host}</span>
                                                </div>
                                            )}
                                            
                                            {packetDetails.analysis.http_info.user_agent && (
                                                <div className={styles.httpItem}>
                                                    <label>User Agent:</label>
                                                    <span className={styles.userAgent}>{packetDetails.analysis.http_info.user_agent}</span>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {packetDetails.analysis?.payload_preview && (
                            <div className={styles.section}>
                                <h4>📄 Payload Preview</h4>
                                <div className={styles.payloadPreview}>
                                    <pre>{packetDetails.analysis.payload_preview}</pre>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {activeTab === 'hexdump' && packetDetails?.hex_dump && (
                <div className={styles.hexDump}>
                    <div className={styles.hexHeader}>
                        <h3>Raw Packet Data</h3>
                        <div className={styles.hexInfo}>
                            Total Size: {packetDetails.analysis?.size || 0} bytes
                        </div>
                    </div>
                    
                    <div className={styles.hexContent}>
                        <pre className={styles.hexData}>
                            {packetDetails.hex_dump.join('\n')}
                        </pre>
                    </div>
                </div>
            )}

            {activeTab === 'details' && !packetDetails && selectedPacket && (
                <div className={styles.noDetails}>
                    <p>Select a packet to view detailed information</p>
                </div>
            )}
        </div>
    );
};

export default PacketInspector;
