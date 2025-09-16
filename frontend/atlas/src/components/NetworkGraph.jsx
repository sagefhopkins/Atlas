import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import axios from 'axios';
import styles from './NetworkGraph.module.css';
import NavigationBar from './NavigationBar';
import PacketInspector from './PacketInspector.jsx';

const GATEWAY_IP = '127.0.0.1';
const LOCAL_NODE = 'LOCAL';
const REMOTE_NODE = 'REMOTE';

const NetworkGraph = () => {
    const svgRef = useRef();
    const [selectedNode, setSelectedNode] = useState(null);
    const [selectedConnection, setSelectedConnection] = useState(null);
    const [allDevices, setAllDevices] = useState([]);
    const [filteredDevices, setFilteredDevices] = useState(null);
    const [activeTab, setActiveTab] = useState('filters');
    const [showGraph, setShowGraph] = useState(true);
    const [showPacketInspector, setShowPacketInspector] = useState(false);
    const nodesRef = useRef([]);
    const linksRef = useRef([]);
    const linkPathsGroupRef = useRef();

    const updateSelectedConnectionLines = () => {
        const group = linkPathsGroupRef.current;
        if (!group) return;
        
        group.selectAll('*').remove();
        
        if (!selectedConnection) return;

        const { src_ip, dst_ip } = selectedConnection;
        const gateway = GATEWAY_IP;
        const points = [];
        const nodeMap = new Map(nodesRef.current.map(n => [n.id, n]));

        if (nodeMap.has(src_ip)) points.push(nodeMap.get(src_ip));
        if (src_ip !== gateway && dst_ip !== gateway && nodeMap.has(gateway)) {
            points.push(nodeMap.get(gateway));
        }
        if (nodeMap.has(dst_ip)) points.push(nodeMap.get(dst_ip));

        for (let i = 0; i < points.length - 1; i++) {
            group.append('line')
                .attr('stroke', '#4caf50')
                .attr('stroke-width', 4)
                .attr('stroke-dasharray', '8,4')
                .attr('x1', points[i].x)
                .attr('y1', points[i].y)
                .attr('x2', points[i + 1].x)
                .attr('y2', points[i + 1].y)
                .style('filter', 'drop-shadow(0 0 6px #4caf50)');
        }
    };

    useEffect(() => {
        axios.get('http://localhost:8000/devices')
            .then(response => {
                setAllDevices(response.data);
                renderGraph(response.data);
            })
            .catch(console.error);
    }, []);

    const renderGraph = (data) => {
        const width = 1400;
        const height = 800;
        const svg = d3.select(svgRef.current)
            .attr("width", width)
            .attr("height", height);
        svg.selectAll("*").remove();

        let zoomLayer = svg.append("g");

        svg.call(d3.zoom()
            .scaleExtent([0.2, 4])
            .on("zoom", (event) => {
                zoomLayer.attr("transform", event.transform);
            }))
            .on("dblclick.zoom", null);

        const nodesMap = new Map();
        const links = [];

        const localNode = { id: "LOCAL", group: "meta", fx: width * 0.25, fy: height / 2 };
        const remoteNode = { id: "REMOTE", group: "meta", fx: width * 0.75, fy: height / 2 };
        const gatewayNode = { id: GATEWAY_IP, group: "gateway", fx: width / 2, fy: height / 2 };

        nodesMap.set("LOCAL", localNode);
        nodesMap.set("REMOTE", remoteNode);
        nodesMap.set(GATEWAY_IP, gatewayNode);

        links.push({ source: "LOCAL", target: GATEWAY_IP });
        links.push({ source: "REMOTE", target: GATEWAY_IP });

        data.forEach(device => {
            const isLocal = device.ip.startsWith("192.168.");
            if (device.ip === GATEWAY_IP) return;

            nodesMap.set(device.ip, {
                id: device.ip,
                group: isLocal ? "lan" : "remote",
                metadata: device.metadata || {}
            });

            links.push({
                source: device.ip,
                target: isLocal ? "LOCAL" : "REMOTE"
            });

            device.connections.forEach(conn => {
                if (conn.src_ip !== conn.dst_ip) {
                    if (!nodesMap.has(conn.dst_ip)) {
                        const isDstLocal = conn.dst_ip.startsWith("192.168.");
                        nodesMap.set(conn.dst_ip, {
                            id: conn.dst_ip,
                            group: isDstLocal ? "lan" : "remote"
                        });
                        links.push({
                            source: conn.dst_ip,
                            target: isDstLocal ? "LOCAL" : "REMOTE"
                        });
                    }
                    links.push({ source: conn.src_ip, target: conn.dst_ip });
                }
            });
        });


        const nodes = Array.from(nodesMap.values());
        nodesRef.current = nodes;
        linksRef.current = links;

        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(25))
            .force('charge', d3.forceManyBody().strength(-100))
            .force('collide', d3.forceCollide(10));

        const linkGroup = zoomLayer.append('g')
            .attr('stroke', '#4a5568')
            .attr('stroke-opacity', 0.6)
            .selectAll('line')
            .data(links)
            .join('line')
            .attr('stroke-width', 1.2);

        const nodeGroup = zoomLayer.append('g')
            .selectAll('g')
            .data(nodes)
            .join('g')
            .call(drag(simulation))
            .on('click', (event, d) => {
                setSelectedNode(d);
                setSelectedConnection(null);
            });

        nodeGroup.append('circle')
            .attr('r', 12)
            .attr('fill', d => {
                if (d.id === LOCAL_NODE || d.id === REMOTE_NODE) return '#718096';
                return d.group === 'gateway' ? '#ffd54f' : d.group === 'lan' ? '#ff8a65' : '#ba68c8';
            })
            .attr('stroke', d => {
                if (d.id === LOCAL_NODE || d.id === REMOTE_NODE) return '#a0aec0';
                return d.group === 'gateway' ? '#ffb300' : d.group === 'lan' ? '#ff5722' : '#9c27b0';
            })
            .attr('stroke-width', 2)
            .style('cursor', 'pointer')
            .style('filter', 'drop-shadow(0 2px 4px rgba(0,0,0,0.4))');

        nodeGroup.append('text')
            .text(d => d.id)
            .attr('x', 15)
            .attr('y', 5)
            .attr('font-size', 11)
            .attr('font-weight', '500')
            .attr('fill', '#e0e0e0')
            .style('pointer-events', 'none')
            .style('text-shadow', '1px 1px 2px rgba(0,0,0,0.8)');

        linkPathsGroupRef.current = zoomLayer.append('g');

        simulation.on('tick', () => {
            linkGroup
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            nodeGroup.attr('transform', d => `translate(${d.x},${d.y})`);
            
            updateSelectedConnectionLines();
        });
    };

    const drag = simulation => d3.drag()
        .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        })
        .on('drag', (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
        })
        .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            if (d.group !== 'gateway' && d.group !== 'meta') {
                d.fx = null;
                d.fy = null;
            }
        });

    useEffect(() => {
        updateSelectedConnectionLines();
    }, [selectedConnection]);

    useEffect(() => {
        if (showGraph && allDevices.length > 0) {
            const timeout = setTimeout(() => {
                renderGraph(allDevices);
            }, 100);
            return () => clearTimeout(timeout);
        }
    }, [showGraph]);


    const totalConnections = allDevices.reduce((total, device) => {
        return total + (device.connections ? device.connections.length : 0);
    }, 0);

    const handleDeviceSelect = (deviceIp) => {
        const targetNode = nodesRef.current.find(node => node.id === deviceIp);
        if (targetNode) {
            setSelectedNode(targetNode);
            setSelectedConnection(null);
        }
    };

    const handleFilterApplied = (filtered) => {
        setFilteredDevices(filtered);
        if (showGraph && filtered) {
            renderGraph(filtered);
        }
    };

    const devicesToDisplay = filteredDevices || allDevices;
    
    const getSelectedConnections = () => {
        if (!selectedNode?.id) return [];
        const device = devicesToDisplay.find(dev => dev.ip === selectedNode.id);
        return device?.connections || [];
    };


    const handleTabChange = (tabId) => {
        if (tabId === 'devices') {
            setShowGraph(!showGraph);
            setActiveTab(showGraph ? 'devices' : 'filters');
            setShowPacketInspector(false);
        } else if (tabId === 'packets') {
            setShowPacketInspector(true);
            setActiveTab(tabId);
        } else {
            setActiveTab(tabId);
            setShowGraph(true);
            setShowPacketInspector(false);
        }
    };

    const getIpClass = (ip) => {
        if (ip === GATEWAY_IP) return styles.gatewayIp;
        if (ip.startsWith('192.168.')) return styles.localIp;
        return styles.remoteIp;
    };

    const getProtocolClass = (protocol) => {
        switch (protocol.toLowerCase()) {
            case 'tcp': return styles.protocolTcp;
            case 'udp': return styles.protocolUdp;
            default: return styles.protocolOther;
        }
    };

    return (
        <div className={styles.container}>
            <NavigationBar 
                activeTab={activeTab} 
                onTabChange={handleTabChange}
                devices={allDevices}
                totalConnections={totalConnections}
                onDeviceSelect={handleDeviceSelect}
                selectedDeviceIp={selectedNode?.id}
                showGraph={showGraph}
                onToggleView={null}
                onFilterApplied={handleFilterApplied}
                filteredDevices={filteredDevices}
                setFilteredDevices={setFilteredDevices}
            />
            
            {showGraph ? (
                <>
                    <div className={styles.layout}>
                        <div className={styles.graphSection}>
                            <h2 className={styles.heading}>Network Topology</h2>
                            <svg ref={svgRef} className={styles.svg} />
                        </div>
                        <div className={styles.sidePanel}>
                            <h3 className={styles.subheading}>Node Metadata</h3>
                            {selectedNode ? (
                                <div className={styles.metadataContainer}>
                                    <div className={styles.metadataItem}>
                                        <strong>IP:</strong> <span className={getIpClass(selectedNode.id)}>{selectedNode.id}</span>
                                    </div>
                                    <div className={styles.metadataItem}>
                                        <strong>Group:</strong> {selectedNode.group}
                                    </div>
                                    {selectedNode.metadata && Object.entries(selectedNode.metadata).map(([k, v]) => (
                                        <div key={k} className={styles.metadataItem}>
                                            <strong>{k}:</strong> {v}
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className={styles.noSelection}>Click a node to view metadata</div>
                            )}
                        </div>
                    </div>

                    <div className={styles.connectionsSection}>
                        <h3 className={styles.subheading}>Connections</h3>
                        <table className={styles.table}>
                            <thead className={styles.tableHeader}>
                                <tr>
                                    <th className={styles.headerCell}>Src IP</th>
                                    <th className={styles.headerCell}>Dst IP</th>
                                    <th className={styles.headerCell}>Protocol</th>
                                    <th className={styles.headerCell}>Src Port</th>
                                    <th className={styles.headerCell}>Dst Port</th>
                                    <th className={styles.headerCell}>Timestamp</th>
                                    <th className={styles.headerCell}>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {selectedNode && getSelectedConnections().length > 0 ? (
                                    getSelectedConnections().map((conn, i) => {
                                        const isSelected = selectedConnection === conn;
                                        const rowClass = `${styles.tableRow} ${
                                            isSelected ? styles.tableRowSelected : 
                                            i % 2 === 0 ? styles.tableRowEven : styles.tableRowOdd
                                        }`;
                                        
                                        return (
                                            <tr
                                                key={i}
                                                className={rowClass}
                                                onClick={() => setSelectedConnection(conn)}
                                            >
                                                <td className={styles.cell}>
                                                    <span className={getIpClass(conn.src_ip)}>{conn.src_ip}</span>
                                                </td>
                                                <td className={styles.cell}>
                                                    <span className={getIpClass(conn.dst_ip)}>{conn.dst_ip}</span>
                                                </td>
                                                <td className={styles.cell}>
                                                    <span className={`${styles.protocol} ${getProtocolClass(conn.protocol)}`}>
                                                        {conn.protocol}
                                                    </span>
                                                </td>
                                                <td className={styles.cell}>
                                                    <span className={styles.port}>{conn.src_port}</span>
                                                </td>
                                                <td className={styles.cell}>
                                                    <span className={styles.port}>{conn.dst_port}</span>
                                                </td>
                                                <td className={styles.cell}>
                                                    <span className={styles.timestamp}>
                                                        {new Date(conn.timestamp * 1000).toLocaleString()}
                                                    </span>
                                                </td>
                                                <td className={styles.cell}>
                                                    <button 
                                                        className={styles.inspectButton}
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            setSelectedConnection(conn);
                                                            setShowPacketInspector(true);
                                                        }}
                                                    >
                                                        🔍 Inspect
                                                    </button>
                                                </td>
                                            </tr>
                                        );
                                    })
                                ) : (
                                    <tr className={styles.emptyRow}>
                                        <td colSpan="7" className={styles.emptyCell}>
                                            {selectedNode
                                                ? 'No connections found for this node.'
                                                : 'Click a node to view its connections.'}
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </>
            ) : (
                <>
                    <div className={styles.layout}>
                        <div className={styles.graphSection}>
                            <h2 className={styles.heading}>Network Devices</h2>
                            <div className={styles.deviceViewContainer}>
                                <div className={styles.deviceStats}>
                                    <div className={styles.statItem}>
                                        <span className={styles.statLabel}>Total Devices:</span>
                                        <span className={styles.statValue}>{allDevices ? allDevices.length : 0}</span>
                                    </div>
                                    <div className={styles.statItem}>
                                        <span className={styles.statLabel}>Active Connections:</span>
                                        <span className={styles.statValue}>{totalConnections || 0}</span>
                                    </div>
                                </div>
                                
                                <div className={styles.deviceList}>
                                    {allDevices && allDevices.length > 0 ? (
                                        <div className={styles.deviceGrid}>
                                            {allDevices.map((device, index) => {
                                                const isLocal = device.ip.startsWith('192.168.');
                                                const isGateway = device.ip === '127.0.0.1';
                                                const connectionCount = device.connections ? device.connections.length : 0;
                                                const isSelected = selectedNode?.id === device.ip;
                                                
                                                return (
                                                    <div 
                                                        key={device.ip} 
                                                        className={`${styles.deviceCard} ${isSelected ? styles.deviceCardSelected : ''}`}
                                                        onClick={() => handleDeviceSelect(device.ip)}
                                                    >
                                                        <div className={styles.deviceHeader}>
                                                            <div className={`${styles.deviceStatus} ${
                                                                isGateway ? styles.statusGateway : 
                                                                isLocal ? styles.statusLocal : styles.statusRemote
                                                            }`}></div>
                                                            <span className={styles.deviceIp}>{device.ip}</span>
                                                            <span className={styles.deviceType}>
                                                                {isGateway ? 'Gateway' : isLocal ? 'Local' : 'Remote'}
                                                            </span>
                                                        </div>
                                                        
                                                        <div className={styles.deviceInfo}>
                                                            <div className={styles.deviceStat}>
                                                                <span className={styles.deviceStatLabel}>Connections:</span>
                                                                <span className={styles.deviceStatValue}>{connectionCount}</span>
                                                            </div>
                                                            
                                                            {device.metadata && Object.keys(device.metadata).length > 0 && (
                                                                <div className={styles.deviceMetadata}>
                                                                    {Object.entries(device.metadata).slice(0, 2).map(([key, value]) => (
                                                                        <div key={key} className={styles.metadataRow}>
                                                                            <span className={styles.metadataKey}>{key}:</span>
                                                                            <span className={styles.metadataValue}>{value}</span>
                                                                        </div>
                                                                    ))}
                                                                    {Object.keys(device.metadata).length > 2 && (
                                                                        <div className={styles.metadataMore}>
                                                                            +{Object.keys(device.metadata).length - 2} more
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            )}
                                                            
                                                            {device.connections && device.connections.length > 0 && (
                                                                <div className={styles.recentConnections}>
                                                                    <div className={styles.connectionsHeader}>Recent Activity:</div>
                                                                    {device.connections.slice(0, 3).map((conn, i) => (
                                                                        <div key={i} className={styles.connectionItem}>
                                                                            <span className={`${styles.protocolBadge} ${
                                                                                conn.protocol.toLowerCase() === 'tcp' ? styles.protocolTcp :
                                                                                conn.protocol.toLowerCase() === 'udp' ? styles.protocolUdp :
                                                                                styles.protocolOther
                                                                            }`}>
                                                                                {conn.protocol}
                                                                            </span>
                                                                            <span className={styles.connectionDetail}>
                                                                                {conn.dst_ip}:{conn.dst_port}
                                                                            </span>
                                                                        </div>
                                                                    ))}
                                                                    {device.connections.length > 3 && (
                                                                        <div className={styles.connectionsMore}>
                                                                            +{device.connections.length - 3} more connections
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            )}
                                                        </div>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    ) : (
                                        <div className={styles.noDevices}>
                                            <div className={styles.noDevicesIcon}>📱</div>
                                            <div className={styles.noDevicesText}>No devices found</div>
                                            <div className={styles.noDevicesSubtext}>Devices will appear here once network data is loaded</div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                        <div className={styles.sidePanel}>
                            <h3 className={styles.subheading}>Device Details</h3>
                            {selectedNode ? (
                                <div className={styles.metadataContainer}>
                                    <div className={styles.metadataItem}>
                                        <strong>IP:</strong> <span className={getIpClass(selectedNode.id)}>{selectedNode.id}</span>
                                    </div>
                                    <div className={styles.metadataItem}>
                                        <strong>Group:</strong> {selectedNode.group}
                                    </div>
                                    {selectedNode.metadata && Object.entries(selectedNode.metadata).map(([k, v]) => (
                                        <div key={k} className={styles.metadataItem}>
                                            <strong>{k}:</strong> {v}
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className={styles.noSelection}>Click a device to view details</div>
                            )}
                        </div>
                    </div>

                    <div className={styles.connectionsSection}>
                        <h3 className={styles.subheading}>Connections</h3>
                        <table className={styles.table}>
                            <thead className={styles.tableHeader}>
                                <tr>
                                    <th className={styles.headerCell}>Src IP</th>
                                    <th className={styles.headerCell}>Dst IP</th>
                                    <th className={styles.headerCell}>Protocol</th>
                                    <th className={styles.headerCell}>Src Port</th>
                                    <th className={styles.headerCell}>Dst Port</th>
                                    <th className={styles.headerCell}>Timestamp</th>
                                    <th className={styles.headerCell}>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {selectedNode && getSelectedConnections().length > 0 ? (
                                    getSelectedConnections().map((conn, i) => {
                                        const isSelected = selectedConnection === conn;
                                        const rowClass = `${styles.tableRow} ${
                                            isSelected ? styles.tableRowSelected : 
                                            i % 2 === 0 ? styles.tableRowEven : styles.tableRowOdd
                                        }`;
                                        
                                        return (
                                            <tr
                                                key={i}
                                                className={rowClass}
                                                onClick={() => setSelectedConnection(conn)}
                                            >
                                                <td className={styles.cell}>
                                                    <span className={getIpClass(conn.src_ip)}>{conn.src_ip}</span>
                                                </td>
                                                <td className={styles.cell}>
                                                    <span className={getIpClass(conn.dst_ip)}>{conn.dst_ip}</span>
                                                </td>
                                                <td className={styles.cell}>
                                                    <span className={`${styles.protocol} ${getProtocolClass(conn.protocol)}`}>
                                                        {conn.protocol}
                                                    </span>
                                                </td>
                                                <td className={styles.cell}>
                                                    <span className={styles.port}>{conn.dst_port}</span>
                                                </td>
                                                <td className={styles.cell}>
                                                    <span className={styles.timestamp}>
                                                        {new Date(conn.timestamp * 1000).toLocaleString()}
                                                    </span>
                                                </td>
                                                <td className={styles.cell}>
                                                    <button 
                                                        className={styles.inspectButton}
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            setSelectedConnection(conn);
                                                            setShowPacketInspector(true);
                                                        }}
                                                    >
                                                        🔍 Inspect
                                                    </button>
                                                </td>
                                            </tr>
                                        );
                                    })
                                ) : (
                                    <tr className={styles.emptyRow}>
                                        <td colSpan="7" className={styles.emptyCell}>
                                            {selectedNode
                                                ? 'No connections found for this device.'
                                                : 'Click a device to view its connections.'}
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </>
            )}
            
            {showPacketInspector && (
                <div>
                    {console.log('📑 Rendering PacketInspector with:', {
                        showPacketInspector,
                        selectedConnection,
                        hasSelectedConnection: !!selectedConnection
                    })}
                    <PacketInspector 
                        selectedConnection={selectedConnection}
                        onClose={() => {
                            console.log('🚪 Closing PacketInspector');
                            setShowPacketInspector(false);
                        }}
                    />
                </div>
            )}
        </div>
    );
};

export default NetworkGraph;
