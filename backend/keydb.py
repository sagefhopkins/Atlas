import redis
import os
import time

class DeviceRecord:
    def __init__(self, ip, mac, metadata=None, connections=None):
        self.ip = ip
        self.mac = mac or "00:00:00:00:00:00"
        self.last_seen = time.time()
        self.metadata = metadata or {}
        self.connections = connections or []

    def update_metadata(self, new_metadata):
        self.metadata.update(new_metadata)
        self.last_seen = time.time()

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "last_seen": self.last_seen,
            "metadata": self.metadata,
            "connections": [conn.to_dict() for conn in self.connections]
        }
    
    @staticmethod
    def from_dict(data):
        connections = [
            ConnectionRecord.from_dict(conn)
            for conn in data.get("connections", [])
        ]
        return DeviceRecord(
            ip=data.get("ip"),
            mac=data.get("mac"),
            metadata=data.get("metadata"),
            connections=connections
        )
class ConnectionRecord:
    def __init__(self, src_ip, dst_ip, src_port=None, dst_port=None, protocol=None, timestamp=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.timestamp = time.time()
        
    def to_dict(self):
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "timestamp": self.timestamp
        }
    @staticmethod
    def from_dict(data):
        return ConnectionRecord(
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            protocol=data.get("protocol"),
            timestamp=data.get("timestamp")
        )

class KeyDBClient:
    def __init__(self, host=None, port=6379, db=0):
        host = host or os.environ.get("KEYDB_HOST", "localhost")
        self.redis = redis.Redis(host=host, port=port, decode_responses=True)
        self.json = self.redis.json()

    def _safe_json_set(self, key, path, obj):
        try:
            self.json.set(key, path, obj)
        except redis.exceptions.ResponseError as e:
            if "WRONGTYPE" in str(e):
                self.redis.delete(key)
                self.json.set(key, path, obj)
            else:
                raise

    def store_device(self, device):
        ip = device.get("src_ip") or device.get("ip")
        mac = device.get("src_mac") or device.get("mac")

        if not ip or not mac:
            return
        key = f"device:{ip}"
        existing = self.get_device(ip)

        if existing:
            record = DeviceRecord(
                ip=existing["ip"],
                mac=existing["mac"],
                metadata=existing.get("metadata", {}),
                connections=[ConnectionRecord(**conn) for conn in existing.get("connections", [])]
            )
            record.update_metadata(device.get("metadata", {}))
        else:
            record = DeviceRecord(
                ip=ip,
                mac=mac,
                metadata=device.get("metadata", {}),
                connections=[]
            )

        self._safe_json_set(key, ".", record.to_dict())
        self.redis.expire(key, 600)

    def store_connection(self, src_ip, dst_ip, src_port=None, dst_port=None, protocol=None):
        link_key = f"link:{src_ip}:{dst_ip}"
        self._safe_json_set(link_key, ".", ConnectionRecord(src_ip, dst_ip).to_dict())

        device_key = f"device:{src_ip}"
        device_data = self.get_device(src_ip)
        if device_data:
            device_data.setdefault("connections", [])
            connection = ConnectionRecord(src_ip, dst_ip, src_port, dst_port, protocol).to_dict()

            if connection not in device_data["connections"]:
                device_data["connections"].append(connection)
                self._safe_json_set(device_key, ".", device_data)
                self.redis.expire(device_key, 600)

    def get_all_devices(self):
        return [self.json.get(k) for k in self.redis.keys("device:*")]

    def get_device(self, ip):
        return self.json.get(f"device:{ip}")
    
    def clear_all(self):
        for k in self.redis.keys("device:*"):
            self.redis.delete(k)
        for k  in self.redis.keys("link:*"):
            self.redis.delete(k)
