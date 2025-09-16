import os
import time
import json
import logging
import redis
from redis.exceptions import ResponseError, RedisError


class DeviceRecord:
    def __init__(self, ip, mac, metadata=None, connections=None, last_seen=None):
        self.ip = ip
        self.mac = mac or "00:00:00:00:00:00"
        self.last_seen = last_seen if last_seen is not None else time.time()
        self.metadata = metadata or {}
        self.connections = connections or []

    def update_metadata(self, new_metadata):
        if new_metadata:
            self.metadata.update(new_metadata)
        self.last_seen = time.time()

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "last_seen": self.last_seen,
            "metadata": self.metadata,
            "connections": [conn.to_dict() if hasattr(conn, 'to_dict') else conn for conn in self.connections],
        }

    @staticmethod
    def from_dict(data):
        if not data:
            return None
        connections = [ConnectionRecord.from_dict(c) for c in data.get("connections", [])]
        return DeviceRecord(
            ip=data.get("ip"),
            mac=data.get("mac"),
            metadata=data.get("metadata"),
            connections=connections,
            last_seen=data.get("last_seen"),
        )


class ConnectionRecord:
    def __init__(self, src_ip, dst_ip, src_port=None, dst_port=None, protocol=None, timestamp=None, packet_id=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.packet_id = packet_id

    def to_dict(self):
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "packet_id": self.packet_id,
        }

    @staticmethod
    def from_dict(data):
        if not data:
            return None
        return ConnectionRecord(
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            protocol=data.get("protocol"),
            timestamp=data.get("timestamp"),
            packet_id=data.get("packet_id"),
        )


class PacketRecord:
    def __init__(self, packet_id, raw_data, headers, analysis, timestamp=None):
        self.packet_id = packet_id
        self.raw_data = raw_data
        self.headers = headers
        self.analysis = analysis
        self.timestamp = timestamp if timestamp is not None else time.time()

    def to_dict(self):
        return {
            "packet_id": self.packet_id,
            "raw_data": self.raw_data,
            "headers": self.headers,
            "analysis": self.analysis,
            "timestamp": self.timestamp,
        }

    @staticmethod
    def from_dict(data):
        if not data:
            return None
        return PacketRecord(
            packet_id=data.get("packet_id"),
            raw_data=data.get("raw_data"),
            headers=data.get("headers"),
            analysis=data.get("analysis"),
            timestamp=data.get("timestamp"),
        )



class KeyDBClient:
    def __init__(self, host="localhost", port=6379, db=0, ttl_seconds=600):
        self.redis = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        self.ttl = int(ttl_seconds)
        self.has_json = self._detect_redisjson()
        self._json_client = self.redis.json() if self.has_json else None
        logging.info(f"KeyDB/Redis connected @ {host}:{port} | RedisJSON: {self.has_json}")

    def _detect_redisjson(self) -> bool:
        try:
            mods = self.redis.execute_command("MODULE", "LIST")
            mod_strs = [str(m).lower() for m in mods]
            if any("rejson" in s or "redisjson" in s for s in mod_strs):
                return True
        except ResponseError:
            pass
        except RedisError:
            pass

        try:
            self.redis.execute_command("JSON.HELLO")
        except ResponseError as e:
            if "unknown command" in str(e).lower():
                return False
            return True
        except RedisError:
            return False
        return True

    def _safe_json_set(self, key: str, path: str, obj: dict):
        payload = json.dumps(obj, separators=(",", ":"))
        if self.has_json and self._json_client:
            try:
                self._json_client.set(key, path, obj)
                return
            except ResponseError as e:
                msg = str(e)
                if "WRONGTYPE" in msg:
                    self.redis.delete(key)
                    self._json_client.set(key, path, obj)
                    return
                if "unknown command" in msg.lower():
                    self.has_json = False
                else:
                    raise
            except RedisError:
                self.has_json = False

        self.redis.set(key, payload)

    def _safe_json_get(self, key: str):
        if self.has_json and self._json_client:
            try:
                return self._json_client.get(key)
            except ResponseError as e:
                if "unknown command" in str(e).lower():
                    self.has_json = False
                else:
                    raise
            except RedisError:
                self.has_json = False

        s = self.redis.get(key)
        if not s:
            return None
        try:
            return json.loads(s)
        except Exception:
            return None

    def store_device(self, device: dict):
        try:
            ip = device.get("src_ip") or device.get("ip")
            mac = device.get("src_mac") or device.get("mac")
            if not ip or not mac:
                return

            key = f"device:{ip}"
            existing = self.get_device(ip)
            if existing:
                record = DeviceRecord.from_dict(existing)
                record.update_metadata(device.get("metadata", {}))
            else:
                record = DeviceRecord(ip=ip, mac=mac, metadata=device.get("metadata", {}), connections=[])

            self._safe_json_set(key, ".", record.to_dict())
            self.redis.expire(key, self.ttl)
        except Exception as e:
            logging.exception(f"store_device failed for {device}: {e}")

    def _conn_dedupe_key(self, c: dict) -> str:
        return f'{c.get("dst_ip")}:{c.get("dst_port")}:{c.get("protocol")}'

    def store_connection(self, src_ip, dst_ip, src_port=None, dst_port=None, protocol=None, packet_id=None):
        try:
            link_key = f"link:{src_ip}:{dst_ip}"
            link_rec = ConnectionRecord(src_ip, dst_ip, src_port, dst_port, protocol, packet_id=packet_id).to_dict()
            self._safe_json_set(link_key, ".", link_rec)
            self.redis.expire(link_key, self.ttl)

            device_key = f"device:{src_ip}"
            device_data = self.get_device(src_ip)
            if not device_data:
                conn_obj = ConnectionRecord(src_ip, dst_ip, src_port, dst_port, protocol, packet_id=packet_id)
                dev = DeviceRecord(ip=src_ip, mac="00:00:00:00:00:00", connections=[conn_obj])
                self._safe_json_set(device_key, ".", dev.to_dict())
                self.redis.expire(device_key, self.ttl)
                return

            conns = device_data.setdefault("connections", [])
            have = {self._conn_dedupe_key(c) for c in conns}
            key_ = self._conn_dedupe_key(link_rec)
            if key_ not in have:
                conns.append(link_rec)
            else:
                for c in conns:
                    if self._conn_dedupe_key(c) == key_:
                        c["timestamp"] = link_rec["timestamp"]
                        if packet_id is not None:
                            c["packet_id"] = packet_id
                        break

            device_data["last_seen"] = time.time()
            self._safe_json_set(device_key, ".", device_data)
            self.redis.expire(device_key, self.ttl)
        except Exception as e:
            logging.exception(f"store_connection failed for {src_ip}->{dst_ip}: {e}")

    def get_all_devices(self):
        try:
            results = []
            for k in self._scan_keys("device:*"):
                data = self._safe_json_get(k)
                if data:
                    results.append(data)
            return results
        except Exception as e:
            logging.exception(f"get_all_devices failed: {e}")
            return []

    def get_device(self, ip):
        try:
            return self._safe_json_get(f"device:{ip}")
        except Exception as e:
            logging.exception(f"get_device failed for {ip}: {e}")
            return None

    def get_all_links(self):
        try:
            results = []
            for k in self._scan_keys("link:*"):
                data = self._safe_json_get(k)
                if data:
                    results.append(data)
            return results
        except Exception as e:
            logging.exception(f"get_all_links failed: {e}")
            return []

    def store_packet(self, packet_record: PacketRecord):
        try:
            key = f"packet:{packet_record.packet_id}"
            self._safe_json_set(key, ".", packet_record.to_dict())
            self.redis.expire(key, self.ttl * 2)
        except Exception as e:
            logging.exception(f"store_packet failed for {packet_record.packet_id}: {e}")

    def get_packet(self, packet_id: str):
        try:
            return self._safe_json_get(f"packet:{packet_id}")
        except Exception as e:
            logging.exception(f"get_packet failed for {packet_id}: {e}")
            return None

    def get_packets_by_connection(self, src_ip: str, dst_ip: str, src_port=None, dst_port=None, protocol=None, limit=50):
        try:
            results = []
            pattern = f"packet:*"
            count = 0
            
            protocol_number = None
            if protocol:
                protocol_map = {
                    'TCP': 6, 'tcp': 6,
                    'UDP': 17, 'udp': 17,
                    'ICMP': 1, 'icmp': 1,
                    'IP': None, 'ip': None
                }
                protocol_number = protocol_map.get(protocol)
            
            for k in self._scan_keys(pattern):
                if count >= limit:
                    break
                    
                data = self._safe_json_get(k)
                if data and data.get("analysis"):
                    analysis = data["analysis"]
                    
                    ip_match = (
                        (analysis.get("src_ip") == src_ip and analysis.get("dst_ip") == dst_ip) or
                        (analysis.get("src_ip") == dst_ip and analysis.get("dst_ip") == src_ip)
                    )
                    
                    port_match = True
                    if src_port is not None:
                        try:
                            analysis_src_port = analysis.get("src_port")
                            analysis_dst_port = analysis.get("dst_port")
                            port_match = port_match and (
                                analysis_src_port == int(src_port) or
                                analysis_dst_port == int(src_port)
                            )
                        except (ValueError, TypeError):
                            pass
                    if dst_port is not None:
                        try:
                            analysis_src_port = analysis.get("src_port")
                            analysis_dst_port = analysis.get("dst_port")
                            port_match = port_match and (
                                analysis_dst_port == int(dst_port) or
                                analysis_src_port == int(dst_port)
                            )
                        except (ValueError, TypeError):
                            pass
                    
                    protocol_match = True
                    if protocol is not None:
                        stored_protocol = analysis.get("protocol")
                        stored_protocol_name = analysis.get("protocol_name", "").lower()
                        
                        if protocol.upper() == "IP" or protocol is None:
                            protocol_match = True
                        else:
                            protocol_match = (
                                stored_protocol == protocol or
                                stored_protocol == protocol_number or
                                stored_protocol_name == protocol.lower() or
                                (protocol.upper() == 'TCP' and stored_protocol == 6) or
                                (protocol.upper() == 'UDP' and stored_protocol == 17) or
                                (protocol.upper() == 'ICMP' and stored_protocol == 1)
                            )
                    
                    if ip_match and port_match and protocol_match:
                        results.append(data)
                        count += 1
                        
            results.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
            return results
        except Exception as e:
            logging.exception(f"get_packets_by_connection failed: {e}")
            return []

    def get_recent_packets(self, limit=100):
        try:
            results = []
            pattern = f"packet:*"
            count = 0
            
            for k in self._scan_keys(pattern):
                if count >= limit * 2:
                    break
                    
                data = self._safe_json_get(k)
                if data:
                    results.append(data)
                    count += 1
                    
            results.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
            return results[:limit]
        except Exception as e:
            logging.exception(f"get_recent_packets failed: {e}")
            return []

    def clear_all(self):
        try:
            to_del = (list(self._scan_keys("device:*")) + 
                     list(self._scan_keys("link:*")) + 
                     list(self._scan_keys("packet:*")))
            if to_del:
                self.redis.delete(*to_del)
        except Exception as e:
            logging.exception(f"clear_all failed: {e}")

    def _scan_keys(self, pattern, count=500):
        cursor = 0
        while True:
            cursor, keys = self.redis.scan(cursor=cursor, match=pattern, count=count)
            for k in keys:
                yield k
            if cursor == 0:
                break

