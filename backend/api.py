from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from keydb import KeyDBClient, DeviceRecord, ConnectionRecord, PacketRecord
from packetcapture import PacketCapture
from packet_analyzer import format_hex_dump
import asyncio
import json
import time
import re

class WiresharkFilter(BaseModel):
    name: str
    filter_expression: str
    description: Optional[str] = None
    enabled: bool = True

class Settings(BaseModel):
    auto_refresh: bool = True
    show_connection_details: bool = False
    enable_animations: bool = True
    refresh_interval: int = 10
    network_interface: Optional[str] = None
    capture_filter: Optional[str] = None

class DeviceStats(BaseModel):
    total_devices: int
    local_devices: int
    remote_devices: int
    total_connections: int
    active_protocols: List[str]

class ConnectionFilter(BaseModel):
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[int] = None
    time_range: Optional[int] = None

app = FastAPI(title="Atlas Network Monitor API", version="1.0.0")
db = KeyDBClient()
packet_capture = PacketCapture()
packet_capture.start()

active_filters = []
current_settings = Settings()
stored_filters = [
    WiresharkFilter(name="HTTP Traffic", filter_expression="tcp.port == 80", description="HTTP web traffic"),
    WiresharkFilter(name="HTTPS Traffic", filter_expression="tcp.port == 443", description="HTTPS secure web traffic"),
    WiresharkFilter(name="DNS Traffic", filter_expression="udp.port == 53", description="Domain name resolution"),
    WiresharkFilter(name="ICMP", filter_expression="icmp", description="Internet Control Message Protocol"),
    WiresharkFilter(name="SSH Traffic", filter_expression="tcp.port == 22", description="Secure Shell connections"),
    WiresharkFilter(name="FTP Traffic", filter_expression="tcp.port == 21", description="File Transfer Protocol"),
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def start_pubsub():
    import threading
    t = threading.Thread(target=listen_for_changes, daemon=True)
    t.start()

@app.get("/devices")
def get_devices():
    return db.get_all_devices()

@app.get("/device/{ip}")
def get_device(ip: str):
    device = db.get_device(ip)
    if device:
        return device
    else:
        return {"error": "Device not found"}, 404
    
@app.get("/graph")
def get_graph():
    return {
        "nodes": db.get_all_devices(),
        "links": db.get_all_links()
    }

@app.post("/clear")
def clear():
    db.clear_all()
    return {"status": "cleared"}


@app.get("/statistics", response_model=DeviceStats)
def get_device_statistics():
    devices = db.get_all_devices()
    
    total_devices = len(devices)
    local_devices = sum(1 for d in devices if d.get('ip', '').startswith('192.168.'))
    remote_devices = total_devices - local_devices
    
    total_connections = sum(len(d.get('connections', [])) for d in devices)
    
    protocols = set()
    for device in devices:
        for conn in device.get('connections', []):
            if conn.get('protocol'):
                protocols.add(conn['protocol'])
    
    return DeviceStats(
        total_devices=total_devices,
        local_devices=local_devices,
        remote_devices=remote_devices,
        total_connections=total_connections,
        active_protocols=list(protocols)
    )

@app.get("/devices/enhanced")
def get_devices_enhanced():
    devices = db.get_all_devices()
    enhanced_devices = []
    
    for device in devices:
        ip = device.get('ip', '')
        connections = device.get('connections', [])
        
        if ip == '127.0.0.1':
            device_type = 'gateway'
        elif ip.startswith('192.168.'):
            device_type = 'local'
        else:
            device_type = 'remote'
        
        enhanced_device = {
            **device,
            'device_type': device_type,
            'connection_count': len(connections),
            'last_activity': max([c.get('timestamp', 0) for c in connections] + [device.get('last_seen', 0)]),
            'protocols': list(set(c.get('protocol', 'Unknown') for c in connections)),
            'is_active': time.time() - device.get('last_seen', 0) < 300  # Active if seen in last 5 minutes
        }
        
        enhanced_devices.append(enhanced_device)
    
    return enhanced_devices

@app.get("/filters", response_model=List[WiresharkFilter])
def get_filters():
    return stored_filters

@app.post("/filters", response_model=WiresharkFilter)
def create_filter(filter_data: WiresharkFilter):
    stored_filters.append(filter_data)
    return filter_data

@app.put("/filters/{filter_name}")
def update_filter(filter_name: str, filter_data: WiresharkFilter):
    for i, f in enumerate(stored_filters):
        if f.name == filter_name:
            stored_filters[i] = filter_data
            return filter_data
    raise HTTPException(status_code=404, detail="Filter not found")

@app.delete("/filters/{filter_name}")
def delete_filter(filter_name: str):
    global stored_filters
    stored_filters = [f for f in stored_filters if f.name != filter_name]
    return {"status": "deleted"}

class FilterRequest(BaseModel):
    filter_expression: str

@app.post("/filters/apply")
def apply_filter(request: FilterRequest):
    try:
        filter_expression = request.filter_expression
        
        if not filter_expression.strip():
            raise HTTPException(status_code=400, detail="Filter expression cannot be empty")
        
        global active_filters
        if filter_expression not in active_filters:
            active_filters.append(filter_expression)
        
        devices = db.get_all_devices()
        filtered_devices = []
        total_filtered_connections = 0
        
        for device in devices:
            filtered_connections = []
            for conn in device.get('connections', []):
                if matches_wireshark_filter(conn, filter_expression):
                    filtered_connections.append(conn)
            
            filtered_device = {
                **device,
                'connections': filtered_connections,
                'filtered_connection_count': len(filtered_connections),
                'original_connection_count': len(device.get('connections', []))
            }
            filtered_devices.append(filtered_device)
            total_filtered_connections += len(filtered_connections)
        
        try:
            broadcast_device_update({
                "type": "filter_applied",
                "filter": filter_expression,
                "filtered_devices": filtered_devices,
                "total_matches": total_filtered_connections,
                "timestamp": time.time()
            })
        except Exception as e:
            print(f"Failed to broadcast filter update: {e}")
        
        return {
            "status": "filter_applied", 
            "filter": filter_expression,
            "devices": filtered_devices,
            "total_matches": total_filtered_connections
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error applying filter: {str(e)}")

@app.post("/filters/clear")
def clear_filters():
    global active_filters
    active_filters = []
    
    try:
        broadcast_device_update({
            "type": "filters_cleared",
            "timestamp": time.time()
        })
    except Exception as e:
        print(f"Failed to broadcast filter clear: {e}")
    
    return {"status": "filters_cleared"}

@app.get("/filters/active")
def get_active_filters():
    return {"active_filters": active_filters}

@app.get("/settings", response_model=Settings)
def get_settings():
    return current_settings

@app.put("/settings", response_model=Settings)
def update_settings(settings: Settings):
    global current_settings
    current_settings = settings
    
    try:
        broadcast_device_update({
            "type": "settings_updated",
            "settings": settings.dict(),
            "timestamp": time.time()
        })
    except Exception as e:
        print(f"Failed to broadcast settings update: {e}")
    
    return current_settings

@app.get("/settings/interfaces")
def get_network_interfaces():
    try:
        import psutil
        interfaces = []
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family.name == 'AF_INET':  # IPv4
                    interfaces.append({
                        "name": interface,
                        "ip": addr.address,
                        "netmask": addr.netmask
                    })
                    break
        return interfaces
    except ImportError:
        return [{"name": "default", "ip": "auto", "netmask": "auto"}]

@app.post("/connections/filter")
def filter_connections(filter_data: ConnectionFilter):
    devices = db.get_all_devices()
    filtered_connections = []
    
    current_time = time.time()
    
    for device in devices:
        for conn in device.get('connections', []):
            # Apply filters
            if filter_data.protocol and conn.get('protocol') != filter_data.protocol:
                continue
            if filter_data.src_ip and conn.get('src_ip') != filter_data.src_ip:
                continue
            if filter_data.dst_ip and conn.get('dst_ip') != filter_data.dst_ip:
                continue
            if filter_data.port and not (conn.get('src_port') == filter_data.port or conn.get('dst_port') == filter_data.port):
                continue
            if filter_data.time_range and (current_time - conn.get('timestamp', 0)) > filter_data.time_range:
                continue
            
            filtered_connections.append(conn)
    
    return {"connections": filtered_connections, "count": len(filtered_connections)}


@app.get("/packets/recent")
def get_recent_packets(limit: int = 50):
    try:
        packets = db.get_recent_packets(limit=limit)
        return {"packets": packets, "count": len(packets)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving packets: {str(e)}")

@app.get("/packets/{packet_id}")
def get_packet_details(packet_id: str):
    try:
        packet = db.get_packet(packet_id)
        if not packet:
            raise HTTPException(status_code=404, detail="Packet not found")
        
        if packet.get("raw_data"):
            packet["hex_dump"] = format_hex_dump(packet["raw_data"])
        
        return packet
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving packet: {str(e)}")

@app.get("/packets/connection/{src_ip}/{dst_ip}")
def get_packets_by_connection(
    src_ip: str, 
    dst_ip: str, 
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    limit: int = 50
):
    try:
        packets = db.get_packets_by_connection(
            src_ip=src_ip, 
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port, 
            protocol=protocol,
            limit=limit
        )
        return {"packets": packets, "count": len(packets)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving packets: {str(e)}")

@app.get("/packets/{packet_id}/export")
def export_packet(packet_id: str, format: str = "json"):
    try:
        packet = db.get_packet(packet_id)
        if not packet:
            raise HTTPException(status_code=404, detail="Packet not found")
        
        if format.lower() == "json":
            return packet
        elif format.lower() == "hex":
            return {"packet_id": packet_id, "hex_data": packet.get("raw_data", "")}
        elif format.lower() == "hexdump":
            hex_data = packet.get("raw_data", "")
            return {
                "packet_id": packet_id, 
                "hex_dump": format_hex_dump(hex_data)
            }
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error exporting packet: {str(e)}")

@app.get("/packets/analysis/summary")
def get_packet_analysis_summary():
    try:
        recent_packets = db.get_recent_packets(limit=1000)  # Analyze last 1000 packets
        
        total_packets = len(recent_packets)
        if total_packets == 0:
            return {
                "total_packets": 0,
                "protocol_distribution": {},
                "packet_types": {},
                "security_summary": {"low_risk": 0, "medium_risk": 0, "high_risk": 0},
                "traffic_direction": {}
            }
        
        protocol_counts = {}
        packet_type_counts = {}
        security_risk_counts = {"low": 0, "medium": 0, "high": 0}
        direction_counts = {}
        
        for packet in recent_packets:
            analysis = packet.get("analysis", {})
            
            protocol = analysis.get("protocol_name", "Unknown")
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            
            packet_type = analysis.get("packet_type", "Unknown")
            packet_type_counts[packet_type] = packet_type_counts.get(packet_type, 0) + 1
            
            security_info = analysis.get("security", {})
            risk_level = security_info.get("risk_level", "low")
            security_risk_counts[risk_level] = security_risk_counts.get(risk_level, 0) + 1
            
            routing = analysis.get("routing", {})
            direction = routing.get("direction", "unknown")
            direction_counts[direction] = direction_counts.get(direction, 0) + 1
        
        return {
            "total_packets": total_packets,
            "protocol_distribution": protocol_counts,
            "packet_types": packet_type_counts,
            "security_summary": security_risk_counts,
            "traffic_direction": direction_counts
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing packets: {str(e)}")

connected_clients = []

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        connected_clients.remove(websocket)
    except Exception as e:
        print(f"Error: {e}")

async def broadcast_update(data):
    for client in connected_clients:
        try:
            await client.send_json(data)
        except Exception as e:
            print(f"Error sending data to client: {e}")


def listen_for_changes():
    pubsub = db.redis.pubsub()
    pubsub.subscribe("events")

    for message in pubsub.listen():
        if message['type'] == 'message':
            try:
                data = json.loads(message['data']) if isinstance(message['data'], str) else message['data']
                asyncio.create_task(broadcast_update(data))
            except json.JSONDecodeError:
                data = {"type": "raw_update", "data": message['data']}
                asyncio.create_task(broadcast_update(data))
            except Exception as e:
                print(f"Error processing pubsub message: {e}")

def broadcast_device_update(device_data, update_type="device_update"):
    try:
        update = {
            "type": update_type,
            "device": device_data,
            "timestamp": time.time()
        }
        db.redis.publish("events", json.dumps(update))
    except Exception as e:
        print(f"Error broadcasting device update: {e}")

def matches_wireshark_filter(connection, filter_expression):
    try:
        if not filter_expression.strip():
            return True
        
        filter_lower = filter_expression.lower().strip()
        conn_protocol = connection.get('protocol', '').lower()
        src_port = connection.get('src_port')
        dst_port = connection.get('dst_port')
        src_ip = connection.get('src_ip', '')
        dst_ip = connection.get('dst_ip', '')
        
        if filter_lower == 'tcp':
            return conn_protocol == 'tcp'
        if filter_lower == 'udp':
            return conn_protocol == 'udp'
        if filter_lower == 'icmp':
            return conn_protocol == 'icmp'
        
        port_pattern = r'(tcp|udp)\.port\s*==\s*(\d+)'
        port_match = re.search(port_pattern, filter_lower)
        if port_match:
            protocol, port = port_match.groups()
            port = int(port)
            
            if conn_protocol == protocol:
                return (src_port == port or dst_port == port)
            return False
        
        src_port_pattern = r'(tcp|udp)\.srcport\s*==\s*(\d+)'
        src_port_match = re.search(src_port_pattern, filter_lower)
        if src_port_match:
            protocol, port = src_port_match.groups()
            port = int(port)
            
            if conn_protocol == protocol:
                return src_port == port
            return False
        
        dst_port_pattern = r'(tcp|udp)\.dstport\s*==\s*(\d+)'
        dst_port_match = re.search(dst_port_pattern, filter_lower)
        if dst_port_match:
            protocol, port = dst_port_match.groups()
            port = int(port)
            
            if conn_protocol == protocol:
                return dst_port == port
            return False
        
        simple_port_pattern = r'port\s*==\s*(\d+)'
        simple_port_match = re.search(simple_port_pattern, filter_lower)
        if simple_port_match:
            port = int(simple_port_match.group(1))
            return (src_port == port or dst_port == port)
        
        ip_src_pattern = r'ip\.src\s*==\s*([\d\.]+)'
        ip_src_match = re.search(ip_src_pattern, filter_lower)
        if ip_src_match:
            target_ip = ip_src_match.group(1)
            return src_ip == target_ip
            
        ip_dst_pattern = r'ip\.dst\s*==\s*([\d\.]+)'
        ip_dst_match = re.search(ip_dst_pattern, filter_lower)
        if ip_dst_match:
            target_ip = ip_dst_match.group(1)
            return dst_ip == target_ip
        
        ip_general_pattern = r'ip\s*==\s*([\d\.]+)'
        ip_general_match = re.search(ip_general_pattern, filter_lower)
        if ip_general_match:
            target_ip = ip_general_match.group(1)
            return (src_ip == target_ip or dst_ip == target_ip)
        
        host_pattern = r'host\s+([\d\.]+)'
        host_match = re.search(host_pattern, filter_lower)
        if host_match:
            target_ip = host_match.group(1)
            return (src_ip == target_ip or dst_ip == target_ip)
        
        net_pattern = r'net\s+([\d\.]+)(?:/([\d]+))?'
        net_match = re.search(net_pattern, filter_lower)
        if net_match:
            network_ip = net_match.group(1)
            subnet_bits = int(net_match.group(2)) if net_match.group(2) else 24
            
            network_parts = network_ip.split('.')
            src_parts = src_ip.split('.')
            dst_parts = dst_ip.split('.')
            
            def ip_in_subnet(ip_parts, net_parts, bits):
                if len(ip_parts) != 4 or len(net_parts) != 4:
                    return False
                
                if bits >= 24:
                    return ip_parts[:3] == net_parts[:3]
                elif bits >= 16:
                    return ip_parts[:2] == net_parts[:2]
                elif bits >= 8:
                    return ip_parts[:1] == net_parts[:1]
                else:
                    return True
            
            return (ip_in_subnet(src_parts, network_parts, subnet_bits) or 
                   ip_in_subnet(dst_parts, network_parts, subnet_bits))
        
        if ' and ' in filter_lower:
            parts = [p.strip() for p in filter_lower.split(' and ')]
            return all(matches_wireshark_filter(connection, part) for part in parts)
        
        if ' or ' in filter_lower:
            parts = [p.strip() for p in filter_lower.split(' or ')]
            return any(matches_wireshark_filter(connection, part) for part in parts)
        
        if filter_lower.startswith('!') or filter_lower.startswith('not '):
            negated_filter = filter_lower[1:].strip() if filter_lower.startswith('!') else filter_lower[4:].strip()
            return not matches_wireshark_filter(connection, negated_filter)
        
        if filter_lower == 'http':
            return conn_protocol == 'tcp' and (src_port == 80 or dst_port == 80)
        if filter_lower == 'https':
            return conn_protocol == 'tcp' and (src_port == 443 or dst_port == 443)
        
        if filter_lower == 'dns':
            return conn_protocol == 'udp' and (src_port == 53 or dst_port == 53)
        
        if filter_lower == 'ssh':
            return conn_protocol == 'tcp' and (src_port == 22 or dst_port == 22)
        
        if filter_lower == 'ftp':
            return conn_protocol == 'tcp' and (src_port == 21 or dst_port == 21)
        
        print(f"Unknown filter pattern: {filter_expression}")
        return False
        
    except Exception as e:
        print(f"Error applying filter {filter_expression}: {e}")
        return False
