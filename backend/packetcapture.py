from scapy.all import sniff, ARP, IP, TCP, UDP, Raw, ICMP, Ether
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS
from pyp0f.database import DATABASE
from pyp0f.fingerprint import fingerprint_mtu, fingerprint_tcp, fingerprint_http
from pyp0f.fingerprint.results import MTUResult, TCPResult, HTTPResult
from multiprocessing import Process, Queue
from keydb import KeyDBClient, DeviceRecord, ConnectionRecord, PacketRecord
from packet_analyzer import create_packet_record
import ipaddress
import signal
import time
import logging
import re
import redis
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional

try:
    DATABASE.load()
    logging.info("p0f database loaded successfully")
except Exception as e:
    logging.error(f"Failed to load p0f database: {e}")
    logging.warning("TCP fingerprinting will be disabled")

def is_local_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
    


def _capture_worker(queue, iface):
    try:
        DATABASE.load()
        logging.info("p0f database loaded successfully in worker process")
    except Exception as e:
        logging.error(f"Failed to load p0f database in worker process: {e}")
        logging.warning("TCP fingerprinting will be disabled in worker process")
    
    db = KeyDBClient(ttl_seconds=60)

    def process_packet(packet):
        
        try:
            packet_record = create_packet_record(packet)
            db.store_packet(packet_record)
            queue.put(packet_record.model_dump())
        except Exception as e:
            print(f"Error storing packet: {e}")
        
        if ARP in packet:
            src_ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            record = DeviceRecord(ip=src_ip, mac=mac, metadata={"type": "ARP"})
            db.store_device(record.model_dump())
        elif IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            mac = getattr(packet, "src", "00:00:00:00:00:00")

            src_port, dst_port, proto = None, None, "IP"
            if TCP in packet:
                src_port, dst_port, proto = packet[TCP].sport, packet[TCP].dport, "TCP"
            elif UDP in packet:
                src_port, dst_port, proto = packet[UDP].sport, packet[UDP].dport, "UDP"

            if is_local_ip(src_ip):
                existing = db.get_device(src_ip)
                if existing:
                    record = DeviceRecord.model_validate(existing)
                    record.update_metadata({"type": proto})
                else:
                    record = DeviceRecord(ip=src_ip, mac=mac, metadata={"type": proto})
                
                packet_id = packet_record.packet_id if 'packet_record' in locals() else None
                record.connections.append(ConnectionRecord(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    packet_id=packet_id
                ))

                db.store_device(record.model_dump())
            
            if is_local_ip(src_ip):
                db.store_connection(src_ip, dst_ip, src_port, dst_port, proto, packet_record.packet_id if 'packet_record' in locals() else None)
            elif is_local_ip(dst_ip):
                db.store_connection(dst_ip, src_ip, src_port, dst_port, proto, packet_record.packet_id if 'packet_record' in locals() else None)

            try:
                if TCP in packet and packet[TCP].flags & 0x02: # SYN flag
                    tcp_result: TCPResult = fingerprint_tcp(packet)
                    if tcp_result.match:
                        os_info = tcp_result.match.record.label
                        os_metadata = {
                            "os": os_info.name,
                            "os_flavor": os_info.flavor,
                            "os_class": os_info.os_class
                        }
                        if is_local_ip(src_ip):
                            existing = db.get_device(src_ip)
                            if existing:
                                record = DeviceRecord.model_validate(existing)
                                record.update_metadata(os_metadata)
                            else:
                                record = DeviceRecord(ip=src_ip, mac=mac, metadata=os_metadata)
                            db.store_device(record.model_dump())
            except Exception as e:
                print(f"Error fingerprinting TCP packet: {e}")

            try:
                if Raw in packet and (HTTPRequest in packet or HTTPResponse in packet):
                    payload = bytes(packet[Raw].load)
                    http_result: HTTPResult = fingerprint_http(payload)
                    if http_result and http_result.app_name:
                        http_metadata = {
                            "http_app": http_result.app_name,
                            "http_version": http_result.version
                        }
                        if is_local_ip(src_ip):
                            existing = db.get_device(src_ip)
                            if existing:
                                record = DeviceRecord.model_validate(existing)
                                record.update_metadata(http_metadata)
                            else:
                                record = DeviceRecord(ip=src_ip, mac=mac, metadata=http_metadata)
                            db.store_device(record.model_dump())
            except Exception as e:
                print(f"Error fingerprinting HTTP packet: {e}")

        else:
            try:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    mac = getattr(packet, "src", "00:00:00:00:00:00")
                    metadata = {"type": "GENERIC", "protocol": "OTHER"}

                    if is_local_ip(src_ip):
                        existing = db.get_device(src_ip)
                        if existing:
                            record = DeviceRecord.model_validate(existing)
                            record.update_metadata(metadata)
                        else:
                            record = DeviceRecord(ip=src_ip, mac=mac, metadata=metadata)

                        packet_id = packet_record.packet_id if 'packet_record' in locals() else None
                        record.connections.append(ConnectionRecord(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=None,
                            dst_port=None,
                            protocol="OTHER",
                            packet_id=packet_id
                        ))
                        db.store_device(record.model_dump())

                    if is_local_ip(src_ip):
                        db.store_connection(src_ip, dst_ip, None, None, "OTHER", packet_record.packet_id if 'packet_record' in locals() else None)
                    elif is_local_ip(dst_ip):
                        db.store_connection(dst_ip, src_ip, None, None, "OTHER", packet_record.packet_id if 'packet_record' in locals() else None)
            except ValueError as e:
                if "Not an HTTP payload" not in str(e):
                    print(f"ValueError processing undefined packet: {e}")
            except Exception as e:
                print(f"Error processing undefined packet: {e}")

    sniff(prn=process_packet, store=0, iface=iface)


class PacketCapture:
    def __init__(self, iface=None):
        self.iface = iface
        self.queue = Queue()
        self.process = None

    def extract_ports(self, packet):
        if TCP in packet:
            return packet[TCP].sport, packet[TCP].dport, "TCP"
        elif UDP in packet:
            return packet[UDP].sport, packet[UDP].dport, "UDP"
        return None, None, None
    
    def process_arp_packet(self, packet):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        mac = packet[ARP].hwsrc

        metadata = {"type": "ARP"}
        record = DeviceRecord(ip=src_ip, mac=mac, metadata=metadata)
        self.db.store_device(record.model_dump())
        self.queue.put(record.model_dump())

    def process_ip_packet(self, packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        mac = getattr(packet, "src", "00:00:00:00:00:00")
        protocol = packet[IP].proto

        src_port, dst_port, protocol = self.extract_ports(packet)

        metadata = {"type": "IP"}

        if is_local_ip(src_ip):
            existing = self.db.get_device(src_ip)
            if existing:
                record = DeviceRecord.model_validate(existing)
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

            self.db.store_device(record.model_dump())
            self.queue.put(record.model_dump())

        if is_local_ip(src_ip):
            self.db.store_connection(src_ip, dst_ip, src_port, dst_port, protocol)
        elif is_local_ip(dst_ip):
            self.db.store_connection(dst_ip, src_ip, src_port, dst_port, protocol)

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
                            record = DeviceRecord.model_validate(existing)
                            record.update_metadata(os_metadata)
                        else:
                            record = DeviceRecord(ip=src_ip, mac=mac, metadata=os_metadata)

                        self.db.store_device(record.model_dump())
                        self.queue.put(record.model_dump())
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
                        record = DeviceRecord.model_validate(existing)
                        record.update_metadata(http_metadata)
                    else:
                        record = DeviceRecord(ip=src_ip, mac=mac, metadata=http_metadata)

                    self.db.store_device(record.model_dump())
                    self.queue.put(record.model_dump())
        except Exception as e:
            print(f"Error fingerprinting HTTP packet: {e}")

    def process_undefined_packet(self, packet, protocol="OTHER"):
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                mac = getattr(packet, "src", "00:00:00:00:00:00")

                metadata = {"type": "GENERIC", "protocol": protocol}

                if is_local_ip(src_ip):
                    existing = self.db.get_device(src_ip)
                    if existing:
                        record = DeviceRecord.model_validate(existing)
                        record.update_metadata(metadata)
                    else:
                        record = DeviceRecord(ip=src_ip, mac=mac, metadata=metadata)

                    record.connections.append(ConnectionRecord(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=None,
                        dst_port=None,
                        protocol=protocol
                    ))

                    self.db.store_device(record.model_dump())
                    self.queue.put(record.model_dump())

                if is_local_ip(src_ip):
                    self.db.store_connection(src_ip, dst_ip, None, None, protocol)
                elif is_local_ip(dst_ip):
                    self.db.store_connection(dst_ip, src_ip, None, None, protocol)
        except ValueError as e:
            if "Not an HTTP payload" not in str(e):
                print(f"ValueError processing undefined packet: {e}")
        except Exception as e:
            print(f"Error processing undefined packet: {e}")


    def start(self):
        self.process = Process(target=_capture_worker, args=(self.queue, self.iface))
        self.process.start()

    def stop(self):
        if self.process and self.process.is_alive():
            self.process.terminate()
            self.process.join()
