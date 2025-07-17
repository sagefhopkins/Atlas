import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import axios from 'axios';

const GATEWAY_IP = '192.168.10.1';
const LOCAL_NODE = 'LOCAL';
const REMOTE_NODE = 'REMOTE';

const NetworkGraph = () => {
    const svgRef = useRef();
    const [selectedNode, setSelectedNode] = useState(null);
    const [selectedConnection, setSelectedConnection] = useState(null);
    const [allDevices, setAllDevices] = useState([]);
    const nodesRef = useRef([]);
    const linksRef = useRef([]);
    const linkPathsGroupRef = useRef();

    const cellStyle = {
        border: '1px solid #ccc',
        padding: '8px',
        textAlign: 'left',
    };

    useEffect(() => {
        axios.get('http://192.168.10.1:8000/devices')
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

        // Link LOCAL and REMOTE to GATEWAY
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
            .force('link', d3.forceLink(links).id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-100))
            .force('collide', d3.forceCollide(10));

        const linkGroup = zoomLayer.append('g')
            .attr('stroke', '#999')
            .attr('stroke-opacity', 0.2)
            .selectAll('line')
            .data(links)
            .join('line')
            .attr('stroke-width', 0.5);

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
            .attr('r', 10)
            .attr('fill', d => {
                if (d.id === LOCAL_NODE || d.id === REMOTE_NODE) return 'gray';
                return d.group === 'gateway' ? 'orange' : d.group === 'lan' ? '#ff6666' : 'purple';
            });

        nodeGroup.append('text')
            .text(d => d.id)
            .attr('x', 12)
            .attr('y', 4)
            .attr('font-size', 12)
            .attr('fill', '#000');

        linkPathsGroupRef.current = zoomLayer.append('g');

        simulation.on('tick', () => {
            linkGroup
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            nodeGroup.attr('transform', d => `translate(${d.x},${d.y})`);
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
                .attr('stroke', 'green')
                .attr('stroke-width', 3)
                .attr('x1', points[i].x)
                .attr('y1', points[i].y)
                .attr('x2', points[i + 1].x)
                .attr('y2', points[i + 1].y);
        }
    }, [selectedConnection]);

    const selectedConnections = allDevices.find(dev => dev.ip === selectedNode?.id)?.connections || [];

    return (
        <div>
            <div style={{ display: 'flex' }}>
                <div style={{ flex: 1 }}>
                    <h2>Network Topology</h2>
                    <svg ref={svgRef} style={{ border: '1px solid #ccc' }} />
                </div>
                <div style={{ width: '300px', marginLeft: '20px' }}>
                    <h3>Node Metadata</h3>
                    {selectedNode ? (
                        <div>
                            <p><strong>IP:</strong> {selectedNode.id}</p>
                            <p><strong>Group:</strong> {selectedNode.group}</p>
                            {selectedNode.metadata && Object.entries(selectedNode.metadata).map(([k, v]) => (
                                <p key={k}><strong>{k}:</strong> {v}</p>
                            ))}
                        </div>
                    ) : <p>Click a node to view metadata</p>}
                </div>
            </div>

            <div style={{ marginTop: '20px' }}>
                <h3>Connections</h3>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                        <tr>
                            <th style={cellStyle}>Src IP</th>
                            <th style={cellStyle}>Dst IP</th>
                            <th style={cellStyle}>Protocol</th>
                            <th style={cellStyle}>Src Port</th>
                            <th style={cellStyle}>Dst Port</th>
                            <th style={cellStyle}>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {selectedNode && selectedConnections.length > 0 ? (
                            selectedConnections.map((conn, i) => (
                                <tr
                                    key={i}
                                    style={{
                                        cursor: 'pointer',
                                        backgroundColor:
                                            selectedConnection === conn ? '#d0f0d0' : i % 2 === 0 ? '#f9f9f9' : '#ffffff',
                                    }}
                                    onClick={() => setSelectedConnection(conn)}
                                >
                                    <td style={cellStyle}>{conn.src_ip}</td>
                                    <td style={cellStyle}>{conn.dst_ip}</td>
                                    <td style={cellStyle}>{conn.protocol}</td>
                                    <td style={cellStyle}>{conn.src_port}</td>
                                    <td style={cellStyle}>{conn.dst_port}</td>
                                    <td style={cellStyle}>
                                        {new Date(conn.timestamp * 1000).toLocaleString()}
                                    </td>
                                </tr>
                            ))
                        ) : (
                            <tr>
                                <td colSpan="6" style={{ ...cellStyle, textAlign: 'center', fontStyle: 'italic' }}>
                                    {selectedNode
                                        ? 'No connections found for this node.'
                                        : 'Click a node to view its connections.'}
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default NetworkGraph;
