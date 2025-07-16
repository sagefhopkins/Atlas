from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from backend.keydb import KeyDBClient
from backend.packetcapture import PacketCapture
import asyncio

app = FastAPI()
db = KeyDBClient()
packet_capture = PacketCapture(iface="eno2")
packet_capture.start()

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
            data = message['data']
            asyncio.run(broadcast_update(data))
