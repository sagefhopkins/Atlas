import React, { useState, useEffect } from 'react';
import './PacketInspector.css';

const PacketInspector = ({ isOpen, onClose, connectionInfo, packetId = null }) => {
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [packets, setPackets] = useState([]);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (isOpen && connectionInfo) {
      fetchPackets();
    }
  }, [isOpen, connectionInfo]);

  useEffect(() => {
    if (packetId && packets.length > 0) {
      const packet = packets.find(p => p.packet_id === packetId);
      if (packet) {
        setSelectedPacket(packet);
      }
    } else if (packets.length > 0) {
      setSelectedPacket(packets[0]);
    }
  }, [packetId, packets]);

  const fetchPackets = async () => {
    if (!connectionInfo) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const { src_ip, dst_ip, src_port, dst_port, protocol } = connectionInfo;
      const params = new URLSearchParams({
        limit: '100'
      });
      
      if (src_port) params.append('src_port', src_port);
      if (dst_port) params.append('dst_port', dst_port);
      if (protocol) params.append('protocol', protocol);

      const response = await fetch(
        `http://localhost:8000/packets/connection/${src_ip}/${dst_ip}?${params}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch packets');
      }
      
      const data = await response.json();
      setPackets(data.packets || []);
      
      if (data.packets && data.packets.length > 0) {
        setSelectedPacket(data.packets[0]);
      }
    } catch (err) {
      setError(err.message);
      console.error('Error fetching packets:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchPacketDetails = async (packetId) => {
    try {
      const response = await fetch(`http://localhost:8000/packets/${packetId}`);
      if (!response.ok) {
        throw new Error('Failed to fetch packet details');
      }
      const data = await response.json();
      setSelectedPacket(data);
    } catch (err) {
      setError(err.message);
      console.error('Error fetching packet details:', err);
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  const formatBytes = (bytes) => {
    return `${bytes} bytes`;
  };

  const formatHexDump = (hexData) => {
    if (!hexData) return [];
    
    const lines = [];
    for (let i = 0; i < hexData.length; i += 32) {
      const chunk = hexData.slice(i, i + 32);
      const offset = (i / 2).toString(16).padStart(8, '0');
      
      let hex = '';
      let ascii = '';
      
      for (let j = 0; j < chunk.length; j += 2) {
        const byteHex = chunk.slice(j, j + 2);
        hex += byteHex + ' ';
        
        const byteVal = parseInt(byteHex, 16);
        ascii += (byteVal >= 32 && byteVal <= 126) ? String.fromCharCode(byteVal) : '.';
      }
      
      lines.push({
        offset,
        hex: hex.padEnd(48, ' '),
        ascii: ascii.padEnd(16, ' ')
      });
    }
    
    return lines;
  };

  const renderPacketList = () => (
    <div className="packet-list">
      <h4>Packets ({packets.length})</h4>
      <div className="packet-list-container">
        {packets.map((packet, index) => (
          <div
            key={packet.packet_id || index}
            className={`packet-item ${selectedPacket?.packet_id === packet.packet_id ? 'selected' : ''}`}
            onClick={() => {
              if (packet.packet_id) {
                fetchPacketDetails(packet.packet_id);
              } else {
                setSelectedPacket(packet);
              }
            }}
          >
            <div className="packet-summary">
              <span className="packet-index">#{index + 1}</span>
              <span className="packet-protocol">{packet.analysis?.protocol_name || 'Unknown'}</span>
              <span className="packet-size">{formatBytes(packet.analysis?.size || 0)}</span>
              <span className="packet-time">
                {packet.analysis?.datetime ? new Date(packet.analysis.datetime).toLocaleTimeString() : 'N/A'}
              </span>
            </div>
            <div className="packet-description">
              {packet.analysis?.summary || 'No description available'}
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  const renderOverviewTab = () => {
    if (!selectedPacket) return <div>No packet selected</div>;

    const analysis = selectedPacket.analysis || {};
    const headers = selectedPacket.headers || {};

    return (
      <div className="tab-content overview-tab">
        <div className="packet-overview">
          <div className="overview-section">
            <h4>Basic Information</h4>
            <div className="info-grid">
              <div className="info-item">
                <label>Packet ID:</label>
                <span>{selectedPacket.packet_id || 'N/A'}</span>
              </div>
              <div className="info-item">
                <label>Size:</label>
                <span>{formatBytes(analysis.size || 0)}</span>
              </div>
              <div className="info-item">
                <label>Type:</label>
                <span>{analysis.packet_type || 'Unknown'}</span>
              </div>
              <div className="info-item">
                <label>Protocol:</label>
                <span>{analysis.protocol_name || 'Unknown'}</span>
              </div>
              <div className="info-item">
                <label>Timestamp:</label>
                <span>{analysis.datetime ? new Date(analysis.datetime).toLocaleString() : 'N/A'}</span>
              </div>
              <div className="info-item">
                <label>Service:</label>
                <span>{analysis.service || 'Unknown'}</span>
              </div>
            </div>
          </div>

          <div className="overview-section">
            <h4>Network Information</h4>
            <div className="info-grid">
              <div className="info-item">
                <label>Source IP:</label>
                <span>{analysis.src_ip || 'N/A'}</span>
              </div>
              <div className="info-item">
                <label>Destination IP:</label>
                <span>{analysis.dst_ip || 'N/A'}</span>
              </div>
              <div className="info-item">
                <label>Source Port:</label>
                <span>{analysis.src_port || 'N/A'}</span>
              </div>
              <div className="info-item">
                <label>Destination Port:</label>
                <span>{analysis.dst_port || 'N/A'}</span>
              </div>
              {analysis.tcp_flags && (
                <div className="info-item">
                  <label>TCP Flags:</label>
                  <span className="tcp-flags">
                    {Object.entries(analysis.tcp_flags)
                      .filter(([, value]) => value)
                      .map(([flag]) => flag.toUpperCase())
                      .join(', ') || 'None'}
                  </span>
                </div>
              )}
              <div className="info-item">
                <label>Connection State:</label>
                <span>{analysis.connection_state || 'N/A'}</span>
              </div>
            </div>
          </div>

          {analysis.routing && (
            <div className="overview-section">
              <h4>Routing Information</h4>
              <div className="info-grid">
                <div className="info-item">
                  <label>Direction:</label>
                  <span>{analysis.routing.direction || 'Unknown'}</span>
                </div>
                <div className="info-item">
                  <label>Traffic Type:</label>
                  <span>{analysis.routing.traffic_type || 'Unknown'}</span>
                </div>
                <div className="info-item">
                  <label>TTL:</label>
                  <span>{analysis.routing.ttl || 'N/A'}</span>
                </div>
                <div className="info-item">
                  <label>Hop Count Estimate:</label>
                  <span>{analysis.routing.hop_count_estimate || 'N/A'}</span>
                </div>
              </div>
            </div>
          )}

          {analysis.security && (
            <div className="overview-section">
              <h4>Security Analysis</h4>
              <div className="info-grid">
                <div className="info-item">
                  <label>Encrypted:</label>
                  <span className={analysis.security.is_encrypted ? 'encrypted' : 'not-encrypted'}>
                    {analysis.security.is_encrypted ? 'Yes' : 'No'}
                  </span>
                </div>
                <div className="info-item">
                  <label>Risk Level:</label>
                  <span className={`risk-level ${analysis.security.risk_level || 'low'}`}>
                    {(analysis.security.risk_level || 'low').toUpperCase()}
                  </span>
                </div>
                <div className="info-item">
                  <label>Suspicious:</label>
                  <span className={analysis.security.is_suspicious ? 'suspicious' : 'normal'}>
                    {analysis.security.is_suspicious ? 'Yes' : 'No'}
                  </span>
                </div>
              </div>
              {analysis.security.warnings && analysis.security.warnings.length > 0 && (
                <div className="security-warnings">
                  <h5>Warnings:</h5>
                  <ul>
                    {analysis.security.warnings.map((warning, index) => (
                      <li key={index} className="warning-item">{warning}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderHeadersTab = () => {
    if (!selectedPacket || !selectedPacket.headers) {
      return <div>No headers available</div>;
    }

    const headers = selectedPacket.headers;

    return (
      <div className="tab-content headers-tab">
        {Object.entries(headers).map(([headerType, headerData]) => (
          <div key={headerType} className="header-section">
            <h4>{headerType.toUpperCase()} Header</h4>
            <div className="header-details">
              {typeof headerData === 'object' ? (
                Object.entries(headerData).map(([key, value]) => (
                  <div key={key} className="header-item">
                    <label>{key.replace(/_/g, ' ').toUpperCase()}:</label>
                    <span>{typeof value === 'object' ? JSON.stringify(value) : String(value)}</span>
                  </div>
                ))
              ) : (
                <div className="header-item">
                  <span>{String(headerData)}</span>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    );
  };

  const renderPayloadTab = () => {
    if (!selectedPacket) return <div>No packet selected</div>;

    const analysis = selectedPacket.analysis || {};
    const payloadPreview = analysis.payload_preview;

    return (
      <div className="tab-content payload-tab">
        <div className="payload-section">
          <h4>Payload Preview</h4>
          {payloadPreview ? (
            <div className="payload-content">
              <pre className="payload-text">{payloadPreview}</pre>
            </div>
          ) : (
            <div className="no-payload">No payload data available</div>
          )}
        </div>

        {selectedPacket.analysis?.dns_info && (
          <div className="payload-section">
            <h4>DNS Information</h4>
            <div className="dns-info">
              {selectedPacket.analysis.dns_info.queries && (
                <div className="dns-queries">
                  <h5>Queries:</h5>
                  {selectedPacket.analysis.dns_info.queries.map((query, index) => (
                    <div key={index} className="dns-query">
                      <span className="dns-name">{query.name}</span>
                      <span className="dns-type">{query.type_name}</span>
                    </div>
                  ))}
                </div>
              )}
              {selectedPacket.analysis.dns_info.answers && (
                <div className="dns-answers">
                  <h5>Answers:</h5>
                  {selectedPacket.analysis.dns_info.answers.map((answer, index) => (
                    <div key={index} className="dns-answer">
                      <span className="dns-name">{answer.name}</span>
                      <span className="dns-type">{answer.type_name}</span>
                      <span className="dns-data">{answer.data}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {selectedPacket.analysis?.http_info && (
          <div className="payload-section">
            <h4>HTTP Information</h4>
            <div className="http-info">
              <div className="info-grid">
                <div className="info-item">
                  <label>Type:</label>
                  <span>{selectedPacket.analysis.http_info.type}</span>
                </div>
                {selectedPacket.analysis.http_info.method && (
                  <div className="info-item">
                    <label>Method:</label>
                    <span>{selectedPacket.analysis.http_info.method}</span>
                  </div>
                )}
                {selectedPacket.analysis.http_info.path && (
                  <div className="info-item">
                    <label>Path:</label>
                    <span>{selectedPacket.analysis.http_info.path}</span>
                  </div>
                )}
                {selectedPacket.analysis.http_info.status_code && (
                  <div className="info-item">
                    <label>Status Code:</label>
                    <span>{selectedPacket.analysis.http_info.status_code}</span>
                  </div>
                )}
                {selectedPacket.analysis.http_info.host && (
                  <div className="info-item">
                    <label>Host:</label>
                    <span>{selectedPacket.analysis.http_info.host}</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderHexTab = () => {
    if (!selectedPacket || !selectedPacket.raw_data) {
      return <div>No raw data available</div>;
    }

    const hexLines = selectedPacket.hex_dump || formatHexDump(selectedPacket.raw_data);

    return (
      <div className="tab-content hex-tab">
        <div className="hex-dump">
          <div className="hex-header">
            <span className="hex-offset">Offset</span>
            <span className="hex-data">Hex Data</span>
            <span className="hex-ascii">ASCII</span>
          </div>
          <div className="hex-content">
            {Array.isArray(hexLines) ? (
              hexLines.map((line, index) => (
                <div key={index} className="hex-line">
                  <span className="hex-offset">{typeof line === 'object' ? line.offset : line.split('  ')[0]}</span>
                  <span className="hex-data">{typeof line === 'object' ? line.hex : line.split('  ')[1]}</span>
                  <span className="hex-ascii">{typeof line === 'object' ? line.ascii : line.split('  ')[2]}</span>
                </div>
              ))
            ) : (
              <pre className="hex-raw">{hexLines}</pre>
            )}
          </div>
        </div>
      </div>
    );
  };

  if (!isOpen) return null;

  return (
    <div className="packet-inspector-overlay">
      <div className="packet-inspector-modal">
        <div className="modal-header">
          <h2>Packet Inspector</h2>
          {connectionInfo && (
            <div className="connection-info">
              {connectionInfo.src_ip}:{connectionInfo.src_port || 'any'} → {connectionInfo.dst_ip}:{connectionInfo.dst_port || 'any'} ({connectionInfo.protocol})
            </div>
          )}
          <button className="close-button" onClick={onClose}>×</button>
        </div>

        <div className="modal-body">
          {loading && <div className="loading">Loading packets...</div>}
          {error && <div className="error">Error: {error}</div>}

          {!loading && !error && (
            <div className="inspector-content">
              <div className="inspector-sidebar">
                {renderPacketList()}
              </div>

              <div className="inspector-main">
                {selectedPacket && (
                  <>
                    <div className="tab-navigation">
                      <button
                        className={`tab-button ${activeTab === 'overview' ? 'active' : ''}`}
                        onClick={() => setActiveTab('overview')}
                      >
                        Overview
                      </button>
                      <button
                        className={`tab-button ${activeTab === 'headers' ? 'active' : ''}`}
                        onClick={() => setActiveTab('headers')}
                      >
                        Headers
                      </button>
                      <button
                        className={`tab-button ${activeTab === 'payload' ? 'active' : ''}`}
                        onClick={() => setActiveTab('payload')}
                      >
                        Payload
                      </button>
                      <button
                        className={`tab-button ${activeTab === 'hex' ? 'active' : ''}`}
                        onClick={() => setActiveTab('hex')}
                      >
                        Hex Dump
                      </button>
                    </div>

                    <div className="tab-container">
                      {activeTab === 'overview' && renderOverviewTab()}
                      {activeTab === 'headers' && renderHeadersTab()}
                      {activeTab === 'payload' && renderPayloadTab()}
                      {activeTab === 'hex' && renderHexTab()}
                    </div>
                  </>
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
