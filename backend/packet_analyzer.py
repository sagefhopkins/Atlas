from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
import hashlib
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
import ipaddress


def generate_packet_id(packet) -> str:
    packet_bytes = bytes(packet)
    timestamp = time.time()
    hash_input = f"{packet_bytes.hex()}{timestamp}".encode()
    return hashlib.sha256(hash_input).hexdigest()[:16]


def extract_raw_data(packet) -> str:
    return bytes(packet).hex()


def parse_ethernet_header(packet) -> Dict[str, Any]:
    if not packet.haslayer(Ether):
        return {}
    
    eth = packet[Ether]
    return {
        "src_mac": str(eth.src),
        "dst_mac": str(eth.dst),
        "type": int(eth.type),
        "type_name": str(eth.sprintf("%Ether.type%"))
    }


def parse_ip_header(packet) -> Dict[str, Any]:
    if not packet.haslayer(IP):
        return {}
    
    ip = packet[IP]
    return {
        "version": int(ip.version) if ip.version is not None else 4,
        "header_length": int(ip.ihl * 4) if ip.ihl is not None else 20,
        "type_of_service": int(ip.tos) if ip.tos is not None else 0,
        "total_length": int(ip.len) if ip.len is not None else None,
        "identification": int(ip.id) if ip.id is not None else 0,
        "flags": {
            "dont_fragment": bool(ip.flags & 2) if ip.flags is not None else False,
            "more_fragments": bool(ip.flags & 1) if ip.flags is not None else False,
            "reserved": bool(ip.flags & 4) if ip.flags is not None else False
        },
        "fragment_offset": int(ip.frag) if ip.frag is not None else 0,
        "ttl": int(ip.ttl) if ip.ttl is not None else 64,
        "protocol": int(ip.proto) if ip.proto is not None else 0,
        "protocol_name": str(ip.sprintf("%IP.proto%")) if ip.proto is not None else "Unknown",
        "checksum": int(ip.chksum) if ip.chksum is not None else None,
        "src_ip": str(ip.src) if ip.src is not None else "0.0.0.0",
        "dst_ip": str(ip.dst) if ip.dst is not None else "0.0.0.0",
        "options": str(ip.options) if ip.options else None
    }


def parse_tcp_header(packet) -> Dict[str, Any]:
    if not packet.haslayer(TCP):
        return {}
    
    tcp = packet[TCP]
    flags = {
        "urg": bool(tcp.flags & 0x20) if tcp.flags is not None else False,
        "ack": bool(tcp.flags & 0x10) if tcp.flags is not None else False,
        "psh": bool(tcp.flags & 0x08) if tcp.flags is not None else False,
        "rst": bool(tcp.flags & 0x04) if tcp.flags is not None else False,
        "syn": bool(tcp.flags & 0x02) if tcp.flags is not None else False,
        "fin": bool(tcp.flags & 0x01) if tcp.flags is not None else False
    }
    
    return {
        "src_port": int(tcp.sport) if tcp.sport is not None else 0,
        "dst_port": int(tcp.dport) if tcp.dport is not None else 0,
        "sequence_number": int(tcp.seq) if tcp.seq is not None else 0,
        "acknowledgment_number": int(tcp.ack) if tcp.ack is not None else 0,
        "data_offset": int(tcp.dataofs) if tcp.dataofs is not None else 20,
        "reserved": int(tcp.reserved) if tcp.reserved is not None else 0,
        "flags": flags,
        "flags_raw": int(tcp.flags) if tcp.flags is not None else 0,
        "window_size": int(tcp.window) if tcp.window is not None else 0,
        "checksum": int(tcp.chksum) if tcp.chksum is not None else None,
        "urgent_pointer": int(tcp.urgptr) if tcp.urgptr is not None else 0,
        "options": str(tcp.options) if tcp.options else None
    }


def parse_udp_header(packet) -> Dict[str, Any]:
    if not packet.haslayer(UDP):
        return {}
    
    udp = packet[UDP]
    return {
        "src_port": int(udp.sport) if udp.sport is not None else 0,
        "dst_port": int(udp.dport) if udp.dport is not None else 0,
        "length": int(udp.len) if udp.len is not None else None,
        "checksum": int(udp.chksum) if udp.chksum is not None else None
    }


def parse_icmp_header(packet) -> Dict[str, Any]:
    if not packet.haslayer(ICMP):
        return {}
    
    icmp = packet[ICMP]
    return {
        "type": int(icmp.type),
        "type_name": str(icmp.sprintf("%ICMP.type%")),
        "code": int(icmp.code),
        "checksum": int(icmp.chksum) if icmp.chksum else None,
        "id": int(icmp.id) if hasattr(icmp, 'id') and icmp.id else None,
        "sequence": int(icmp.seq) if hasattr(icmp, 'seq') and icmp.seq else None
    }


def parse_dns_data(packet) -> Dict[str, Any]:
    if not packet.haslayer(DNS):
        return {}
    
    dns = packet[DNS]
    
    queries = []
    if dns.qd:
        for i in range(int(dns.qdcount)):
            if i < len(dns.qd):
                q = dns.qd[i]
                queries.append({
                    "name": q.qname.decode() if isinstance(q.qname, bytes) else str(q.qname),
                    "type": int(q.qtype),
                    "type_name": str(q.sprintf("%DNSQR.qtype%")),
                    "class": int(q.qclass)
                })
    
    answers = []
    if dns.an:
        for i in range(int(dns.ancount)):
            if i < len(dns.an):
                a = dns.an[i]
                try:
                    if hasattr(a, 'rdata') and a.rdata is not None:
                        data_str = str(a.rdata)
                    else:
                        data_str = "N/A"
                except Exception:
                    data_str = "[parsing error]"
                
                answers.append({
                    "name": a.rrname.decode() if isinstance(a.rrname, bytes) else str(a.rrname),
                    "type": int(a.type),
                    "type_name": str(a.sprintf("%DNSRR.type%")),
                    "class": int(a.rclass),
                    "ttl": int(a.ttl),
                    "data": data_str
                })
    
    return {
        "id": int(dns.id),
        "is_response": bool(dns.qr),
        "opcode": int(dns.opcode),
        "authoritative": bool(dns.aa),
        "truncated": bool(dns.tc),
        "recursion_desired": bool(dns.rd),
        "recursion_available": bool(dns.ra),
        "response_code": int(dns.rcode),
        "response_code_name": str(dns.sprintf("%DNS.rcode%")),
        "question_count": int(dns.qdcount),
        "answer_count": int(dns.ancount),
        "authority_count": int(dns.nscount),
        "additional_count": int(dns.arcount),
        "queries": queries,
        "answers": answers
    }


def parse_http_data(packet) -> Dict[str, Any]:
    http_data = {}
    
    if packet.haslayer(HTTPRequest):
        http_req = packet[HTTPRequest]
        http_data.update({
            "type": "request",
            "method": http_req.Method.decode() if isinstance(http_req.Method, bytes) else str(http_req.Method),
            "path": http_req.Path.decode() if isinstance(http_req.Path, bytes) else str(http_req.Path),
            "version": http_req.Http_Version.decode() if isinstance(http_req.Http_Version, bytes) else str(http_req.Http_Version),
            "host": http_req.Host.decode() if hasattr(http_req, 'Host') and http_req.Host else None,
            "user_agent": http_req.User_Agent.decode() if hasattr(http_req, 'User_Agent') and http_req.User_Agent else None
        })
    
    if packet.haslayer(HTTPResponse):
        http_resp = packet[HTTPResponse]
        http_data.update({
            "type": "response",
            "status_code": http_resp.Status_Code.decode() if isinstance(http_resp.Status_Code, bytes) else str(http_resp.Status_Code),
            "reason_phrase": http_resp.Reason_Phrase.decode() if isinstance(http_resp.Reason_Phrase, bytes) else str(http_resp.Reason_Phrase),
            "version": http_resp.Http_Version.decode() if isinstance(http_resp.Http_Version, bytes) else str(http_resp.Http_Version),
            "content_type": http_resp.Content_Type.decode() if hasattr(http_resp, 'Content_Type') and http_resp.Content_Type else None,
            "content_length": http_resp.Content_Length.decode() if hasattr(http_resp, 'Content_Length') and http_resp.Content_Length else None
        })
    
    return http_data


def get_payload_preview(packet, max_length=200) -> Optional[str]:
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw])
        if len(payload) > 0:
            try:
                text = payload.decode('utf-8', errors='ignore')[:max_length]
                if text.isprintable():
                    return text
            except:
                pass
            
            return payload[:max_length].hex()
    
    return None


def classify_packet_type(packet) -> str:
    if packet.haslayer(ARP):
        return "ARP"
    elif packet.haslayer(DNS):
        return "DNS"
    elif packet.haslayer(HTTPRequest):
        return "HTTP_REQUEST"
    elif packet.haslayer(HTTPResponse):
        return "HTTP_RESPONSE"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(IP):
        return "IP"
    else:
        return "OTHER"


def analyze_routing_info(packet) -> Dict[str, Any]:
    routing_info = {}
    
    if packet.haslayer(IP):
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        
        try:
            src_private = ipaddress.ip_address(src_ip).is_private
            dst_private = ipaddress.ip_address(dst_ip).is_private
        except:
            src_private = dst_private = False
        
        routing_info.update({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_is_private": src_private,
            "dst_is_private": dst_private,
            "ttl": ip.ttl,
            "hop_count_estimate": 64 - ip.ttl if ip.ttl <= 64 else 255 - ip.ttl
        })
        
        if src_private and not dst_private:
            routing_info["direction"] = "outbound"
            routing_info["traffic_type"] = "local_to_internet"
        elif not src_private and dst_private:
            routing_info["direction"] = "inbound"
            routing_info["traffic_type"] = "internet_to_local"
        elif src_private and dst_private:
            routing_info["direction"] = "internal"
            routing_info["traffic_type"] = "local_to_local"
        else:
            routing_info["direction"] = "transit"
            routing_info["traffic_type"] = "internet_to_internet"
    
    return routing_info


def analyze_packet_comprehensive(packet) -> Dict[str, Any]:
    analysis = {
        "packet_type": classify_packet_type(packet),
        "size": len(packet),
        "timestamp": time.time(),
        "routing": analyze_routing_info(packet),
        "payload_preview": get_payload_preview(packet)
    }
    
    if packet.haslayer(IP):
        ip = packet[IP]
        analysis.update({
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "protocol": ip.proto,
            "protocol_name": ip.sprintf("%IP.proto%")
        })
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            analysis.update({
                "src_port": tcp.sport,
                "dst_port": tcp.dport,
                "tcp_flags": {
                    "syn": bool(tcp.flags & 0x02),
                    "ack": bool(tcp.flags & 0x10),
                    "fin": bool(tcp.flags & 0x01),
                    "rst": bool(tcp.flags & 0x04),
                    "psh": bool(tcp.flags & 0x08),
                    "urg": bool(tcp.flags & 0x20)
                },
                "connection_state": get_tcp_connection_state(tcp)
            })
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            analysis.update({
                "src_port": udp.sport,
                "dst_port": udp.dport,
                "udp_length": udp.len
            })
    
    if packet.haslayer(DNS):
        dns_info = parse_dns_data(packet)
        analysis["dns_info"] = dns_info
        analysis["service"] = "DNS"
    elif packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        http_info = parse_http_data(packet)
        analysis["http_info"] = http_info
        analysis["service"] = "HTTP"
    else:
        analysis["service"] = identify_service_by_port(analysis.get("src_port"), analysis.get("dst_port"))
    
    return analysis


def get_tcp_connection_state(tcp) -> str:
    flags = tcp.flags
    
    if flags & 0x02 and not (flags & 0x10):  # SYN only
        return "SYN_SENT"
    elif flags & 0x02 and flags & 0x10:  # SYN+ACK
        return "SYN_RECEIVED"
    elif flags & 0x10 and not (flags & 0x02):  # ACK only
        return "ESTABLISHED"
    elif flags & 0x01:  # FIN
        return "FIN_WAIT"
    elif flags & 0x04:  # RST
        return "RESET"
    elif flags & 0x08:  # PSH
        return "PUSH_DATA"
    else:
        return "UNKNOWN"


def identify_service_by_port(src_port: Optional[int], dst_port: Optional[int]) -> str:
    well_known_ports = {
        21: "FTP",
        22: "SSH", 
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        3389: "RDP",
        5432: "PostgreSQL",
        3306: "MySQL",
        27017: "MongoDB",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt"
    }
    
    if dst_port and dst_port in well_known_ports:
        return well_known_ports[dst_port]
    elif src_port and src_port in well_known_ports:
        return well_known_ports[src_port]
    
    if dst_port and dst_port < 1024:
        return f"Service-{dst_port}"
    elif src_port and src_port < 1024:
        return f"Service-{src_port}"
    
    return "Unknown"


def get_packet_summary(packet) -> str:
    if packet.haslayer(ARP):
        arp = packet[ARP]
        return f"ARP {arp.op} from {arp.psrc} ({arp.hwsrc}) to {arp.pdst}"
    
    elif packet.haslayer(IP):
        ip = packet[IP]
        summary = f"{ip.sprintf('%IP.proto%')} {ip.src} → {ip.dst}"
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = []
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x08: flags.append("PSH")
            if tcp.flags & 0x20: flags.append("URG")
            
            flag_str = ",".join(flags) if flags else "No flags"
            summary += f" [{flag_str}] {tcp.sport}→{tcp.dport}"
            
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            summary += f" {udp.sport}→{udp.dport}"
            
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            summary += f" {icmp.sprintf('%ICMP.type%')}"
    
    else:
        summary = f"Unknown packet type (length: {len(packet)})"
    
    return summary


def get_security_analysis(packet) -> Dict[str, Any]:
    security_info = {
        "is_encrypted": False,
        "is_suspicious": False,
        "warnings": [],
        "risk_level": "low"
    }
    
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        encrypted_ports = [443, 22, 993, 995, 465, 587, 636]
        if tcp.sport in encrypted_ports or tcp.dport in encrypted_ports:
            security_info["is_encrypted"] = True
    
    if packet.haslayer(IP):
        ip = packet[IP]
        
        try:
            src_private = ipaddress.ip_address(ip.src).is_private
            dst_private = ipaddress.ip_address(ip.dst).is_private
            
            suspicious_ranges = [
                "10.0.0.0/8",
                "172.16.0.0/12", 
                "169.254.0.0/16"  # Link-local
            ]
            
            for range_str in suspicious_ranges:
                network = ipaddress.ip_network(range_str)
                if (ipaddress.ip_address(ip.src) in network or 
                    ipaddress.ip_address(ip.dst) in network):
                    security_info["warnings"].append(f"Traffic involving reserved range: {range_str}")
                    
        except:
            pass
    
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        if tcp.flags == 0:  # Null scan
            security_info["warnings"].append("TCP null scan detected")
            security_info["is_suspicious"] = True
        elif tcp.flags == 0x3F:  # All flags set
            security_info["warnings"].append("TCP XMAS scan detected")
            security_info["is_suspicious"] = True
        elif tcp.flags & 0x06 == 0x06:  # SYN+RST
            security_info["warnings"].append("Unusual TCP SYN+RST combination")
    
    if security_info["is_suspicious"] or len(security_info["warnings"]) > 0:
        security_info["risk_level"] = "medium"
    if len(security_info["warnings"]) > 2:
        security_info["risk_level"] = "high"
    
    return security_info


def make_json_serializable(obj) -> Any:
    if isinstance(obj, dict):
        return {key: make_json_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [make_json_serializable(item) for item in obj]
    elif hasattr(obj, '__int__'):  # Scapy field types like FlagValue
        return int(obj)
    elif hasattr(obj, '__str__') and not isinstance(obj, (str, int, float, bool, type(None))):
        return str(obj)
    else:
        return obj

def create_packet_record(packet) -> 'PacketRecord':
    from keydb import PacketRecord
    
    try:
        packet_id = generate_packet_id(packet)
        raw_data = extract_raw_data(packet)
        
        headers = {}
        try:
            headers["ethernet"] = parse_ethernet_header(packet)
        except Exception as e:
            print(f"Error parsing ethernet header: {e}")
            
        try:
            headers["ip"] = parse_ip_header(packet)
        except Exception as e:
            print(f"Error parsing IP header: {e}")
            
        try:
            headers["tcp"] = parse_tcp_header(packet)
        except Exception as e:
            print(f"Error parsing TCP header: {e}")
            
        try:
            headers["udp"] = parse_udp_header(packet)
        except Exception as e:
            print(f"Error parsing UDP header: {e}")
            
        try:
            headers["icmp"] = parse_icmp_header(packet)
        except Exception as e:
            print(f"Error parsing ICMP header: {e}")
            
        try:
            headers["dns"] = parse_dns_data(packet)
        except Exception as e:
            print(f"Error parsing DNS data: {e}")
            
        try:
            headers["http"] = parse_http_data(packet)
        except Exception as e:
            print(f"Error parsing HTTP data: {e}")
        
        headers = {k: v for k, v in headers.items() if v}
        
        try:
            analysis = analyze_packet_comprehensive(packet)
            analysis["summary"] = get_packet_summary(packet)
            analysis["security"] = get_security_analysis(packet)
            analysis["datetime"] = datetime.fromtimestamp(time.time()).isoformat()
        except Exception as e:
            print(f"Error in packet analysis: {e}")
            analysis = {
                "packet_type": "UNKNOWN",
                "size": len(packet),
                "timestamp": time.time(),
                "summary": f"Packet parsing error: {e}",
                "datetime": datetime.fromtimestamp(time.time()).isoformat()
            }
        
        headers = make_json_serializable(headers)
        analysis = make_json_serializable(analysis)
        
        return PacketRecord(
            packet_id=packet_id,
            raw_data=raw_data,
            headers=headers,
            analysis=analysis
        )
        
    except Exception as e:
        print(f"Critical error creating packet record: {e}")
        packet_id = hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:16]
        return PacketRecord(
            packet_id=packet_id,
            raw_data="",
            headers={},
            analysis={
                "packet_type": "ERROR",
                "size": 0,
                "timestamp": time.time(),
                "summary": f"Packet processing failed: {e}",
                "datetime": datetime.fromtimestamp(time.time()).isoformat()
            }
        )


def format_hex_dump(hex_data: str, bytes_per_line=16) -> List[str]:
    lines = []
    for i in range(0, len(hex_data), bytes_per_line * 2):
        chunk = hex_data[i:i + bytes_per_line * 2]
        
        try:
            byte_data = bytes.fromhex(chunk)
            ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in byte_data)
        except:
            ascii_repr = '.' * (len(chunk) // 2)
        
        hex_formatted = ' '.join(chunk[j:j+2] for j in range(0, len(chunk), 2))
        
        offset = f"{i//2:08x}"
        
        hex_formatted = hex_formatted.ljust(bytes_per_line * 3)
        
        lines.append(f"{offset}  {hex_formatted}  {ascii_repr}")
    
    return lines
