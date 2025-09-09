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
        "src_mac": eth.src,
        "dst_mac": eth.dst,
        "type": eth.type,
        "type_name": eth.sprintf("%Ether.type%")
    }


def parse_ip_header(packet) -> Dict[str, Any]:
    if not packet.haslayer(IP):
        return {}
    
    ip = packet[IP]
    return {
        "version": ip.version,
        "header_length": ip.ihl * 4,
        "type_of_service": ip.tos,
        "total_length": ip.len,
        "identification": ip.id,
        "flags": {
            "dont_fragment": bool(ip.flags & 2),
            "more_fragments": bool(ip.flags & 1),
            "reserved": bool(ip.flags & 4)
        },
        "fragment_offset": ip.frag,
        "ttl": ip.ttl,
        "protocol": ip.proto,
        "protocol_name": ip.sprintf("%IP.proto%"),
        "checksum": ip.chksum,
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "options": str(ip.options) if ip.options else None
    }


def parse_tcp_header(packet) -> Dict[str, Any]:
    if not packet.haslayer(TCP):
        return {}
    
    tcp = packet[TCP]
    flags = {
        "urg": bool(tcp.flags & 0x20),
        "ack": bool(tcp.flags & 0x10),
        "psh": bool(tcp.flags & 0x08),
        "rst": bool(tcp.flags & 0x04),
        "syn": bool(tcp.flags & 0x02),
        "fin": bool(tcp.flags & 0x01)
    }
    
    return {
        "src_port": tcp.sport,
        "dst_port": tcp.dport,
        "sequence_number": tcp.seq,
        "acknowledgment_number": tcp.ack,
        "data_offset": tcp.dataofs,
        "reserved": tcp.reserved,
        "flags": flags,
        "flags_raw": tcp.flags,
        "window_size": tcp.window,
        "checksum": tcp.chksum,
        "urgent_pointer": tcp.urgptr,
        "options": str(tcp.options) if tcp.options else None
    }


def parse_udp_header(packet) -> Dict[str, Any]:
    if not packet.haslayer(UDP):
        return {}
    
    udp = packet[UDP]
    return {
        "src_port": udp.sport,
        "dst_port": udp.dport,
        "length": udp.len,
        "checksum": udp.chksum
    }


def parse_icmp_header(packet) -> Dict[str, Any]:
    if not packet.haslayer(ICMP):
        return {}
    
    icmp = packet[ICMP]
    return {
        "type": icmp.type,
        "type_name": icmp.sprintf("%ICMP.type%"),
        "code": icmp.code,
        "checksum": icmp.chksum,
        "id": icmp.id if hasattr(icmp, 'id') else None,
        "sequence": icmp.seq if hasattr(icmp, 'seq') else None
    }


def parse_dns_data(packet) -> Dict[str, Any]:
    if not packet.haslayer(DNS):
        return {}
    
    dns = packet[DNS]
    
    queries = []
    if dns.qd:
        for i in range(dns.qdcount):
            if i < len(dns.qd):
                q = dns.qd[i]
                queries.append({
                    "name": q.qname.decode() if isinstance(q.qname, bytes) else str(q.qname),
                    "type": q.qtype,
                    "type_name": q.sprintf("%DNSQR.qtype%"),
                    "class": q.qclass
                })
    
    answers = []
    if dns.an:
        for i in range(dns.ancount):
            if i < len(dns.an):
                a = dns.an[i]
                answers.append({
                    "name": a.rrname.decode() if isinstance(a.rrname, bytes) else str(a.rrname),
                    "type": a.type,
                    "type_name": a.sprintf("%DNSRR.type%"),
                    "class": a.rclass,
                    "ttl": a.ttl,
                    "data": str(a.rdata)
                })
    
    return {
        "id": dns.id,
        "is_response": bool(dns.qr),
        "opcode": dns.opcode,
        "authoritative": bool(dns.aa),
        "truncated": bool(dns.tc),
        "recursion_desired": bool(dns.rd),
        "recursion_available": bool(dns.ra),
        "response_code": dns.rcode,
        "response_code_name": dns.sprintf("%DNS.rcode%"),
        "question_count": dns.qdcount,
        "answer_count": dns.ancount,
        "authority_count": dns.nscount,
        "additional_count": dns.arcount,
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


def create_packet_record(packet) -> 'PacketRecord':
    from keydb import PacketRecord
    
    packet_id = generate_packet_id(packet)
    raw_data = extract_raw_data(packet)
    
    # Parse all headers
    headers = {
        "ethernet": parse_ethernet_header(packet),
        "ip": parse_ip_header(packet),
        "tcp": parse_tcp_header(packet),
        "udp": parse_udp_header(packet),
        "icmp": parse_icmp_header(packet),
        "dns": parse_dns_data(packet),
        "http": parse_http_data(packet)
    }
    
    # Remove empty headers
    headers = {k: v for k, v in headers.items() if v}
    
    # Comprehensive analysis
    analysis = analyze_packet_comprehensive(packet)
    analysis["summary"] = get_packet_summary(packet)
    analysis["security"] = get_security_analysis(packet)
    analysis["datetime"] = datetime.fromtimestamp(time.time()).isoformat()
    
    return PacketRecord(
        packet_id=packet_id,
        raw_data=raw_data,
        headers=headers,
        analysis=analysis
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
