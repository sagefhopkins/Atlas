from scapy.all import sniff, ARP, IP, TCP, UDP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from pyp0f.database import DATABASE
from pyp0f.fingerprint import fingerprint_mtu, fingerprint_tcp, fingerprint_http
from pyp0f.fingerprint.results import MTUResult, TCPResult, HTTPResult
from multiprocessing import Process, Queue
from backend.keydb import KeyDBClient, DeviceRecord, ConnectionRecord
import ipaddress
import signal
import time

def is_local_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
    


class PacketCapture:
    def __init__(self, iface=None):
        self.iface = iface
        self.queue = Queue()
        self.process = None
        self.db = KeyDBClient()
        DATABASE.load()

    def process_arp_packet(self, packet):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        mac = packet[ARP].hwsrc

        metadata = {"type": "ARP"}
        record = DeviceRecord(ip=src_ip, mac=mac, metadata=metadata)
        self.db.store_device(record.to_dict())
        self.queue.put(record.to_dict())

    def process_ip_packet(self, packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        mac = getattr(packet, "src", "00:00:00:00:00:00")
        protocol = packet[IP].proto

        src_port, dst_port = extract_ports(packet)

        metadata = {"type": "IP"}

        if is_local_ip(src_ip):
            existing = self.db.get_device(src_ip)
            if existing:
                record = DeviceRecord(
                    ip=existing["ip"],
                    mac=existing["mac"],
                    metadata=existing.get("metadata", {}),
                    connections=[ConnectionRecord(**conn) for conn in existing.get("connections", [])]
                )
                record.update_metadata(metadata)
            else:
                record = DeviceRecord(ip=src_ip, mac=mac, metadata=metadata)

            record.connections.append(ConnectionRecord(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol
            ))

            self.db.store_device(record.to_dict())
            self.queue.put(record.to_dict())

        if is_local_ip(src_ip):
            self.db.store_connection(src_ip, dst_ip)
        elif is_local_ip(dst_ip):
            self.db.store_connection(dst_ip, src_ip)

    def extract_ports(self, packet):
        if TCP in packet:
            return packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            return packet[UDP].sport, packet[UDP].dport
        return None, None
    
    def enrich_with_os_fingerprint(self, packet):
        try:
            if packet[TCP].flags & 0x02:
                tcp_result: TCPResult = fingerprint_tcp(packet)
                if tcp_result.match:
                    src_ip = packet[IP].src
                    mac = getattr(packet, "src", "00:00:00:00:00:00")
                    os_info = tcp_result.match.record.label
                    os_metadata = {
                        "os": os_info.name,
                        "os_flavor": os_info.flavor,
                        "os_class": os_info.os_class
                    }

                    if is_local_ip(src_ip):
                        existing = self.db.get_device(src_ip)
                        if existing:
                            record = DeviceRecord(
                                ip=existing["ip"],
                                mac=existing["mac"],
                                metadata=existing.get("metadata", {}),
                                connections=[ConnectionRecord(**conn) for conn in existing.get("connections", [])]
                            )
                            record.update_metadata(os_metadata)
                        else:
                            record = DeviceRecord(ip=src_ip, mac=mac, metadata=os_metadata)

                        self.db.store_device(record.to_dict())
                        self.queue.put(record.to_dict())
        except Exception as e:
            print(f"Error fingerprinting TCP packet: {e}")

    def enrich_with_http_fingerprint(self, packet):
        try:
            payload = bytes(packet[Raw].load)
            http_result: HTTPResult = fingerprint_http(payload)
            if http_result and http_result.app_name:
                http_metadata = {
                    "http_app": http_result.app_name,
                    "http_version": http_result.version
                }

                src_ip = packet[IP].src
                mac = getattr(packet, "src", "00:00:00:00:00:00")

                if is_local_ip(src_ip):
                    existing = self.db.get_device(src_ip)
                    if existing:
                        record = DeviceRecord(
                            ip=existing["ip"],
                            mac=existing["mac"],
                            metadata=existing.get("metadata", {}),
                            connections=[ConnectionRecord(**conn) for conn in existing.get("connections", [])]
                        )
                        record.update_metadata(http_metadata)
                    else:
                        record = DeviceRecord(ip=src_ip, mac=mac, metadata=http_metadata)

                    self.db.store_device(record.to_dict())
                    self.queue.put(record.to_dict())
        except Exception as e:
            print(f"Error fingerprinting HTTP packet: {e}")

    def capture_loop(self, queue, iface):
        def handle_packet(packet):
            if ARP in packet and packet[ARP].op in (1, 2):
                self.process_arp_packet(packet)
            elif IP in packet:
                self.process_ip_packet(packet)

            if TCP in packet and IP in packet:
                self.enrich_with_os_fingerprint(packet)

            if packet.haslayer(HTTPResponse) and Raw in packet:
                self.enrich_with_http_fingerprint(packet)
                
        sniff(iface=iface, prn=handle_packet, store=False)

    def start(self):
        self.process = Process(target=self.capture_loop, args=(self.queue, self.iface))
        self.process.start()

    def stop(self):
        if self.process and self.process.is_alive():
            self.process.terminate()
            self.process.join()