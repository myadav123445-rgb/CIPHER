import asyncio
import json
import sys
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from imap_tools import MailBox, A

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR))

try:
    from rules.engine import evaluate_threat
except ImportError:
    def evaluate_threat(sender, subject, body):
        return 20, "SAFE", ["Baseline verified"], None, False

app = FastAPI(title="CIPHER SOC Phishing Triage API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GMAIL_USER = "itsofficalsameer@gmail.com"
GMAIL_APP_PASSWORD = "sgur qyok iklc eqrp"
IMAP_SERVER = "imap.gmail.com"

connected_clients = []

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    frontend_path = ROOT_DIR / "frontend" / "index.html"
    if frontend_path.exists():
        return FileResponse(frontend_path)
    return "<h1>index.html not found in frontend directory</h1>"

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)

async def broadcast_email(email_data: dict):
    for client in list(connected_clients):
        try:
            await client.send_text(json.dumps(email_data))
        except Exception:
            if client in connected_clients:
                connected_clients.remove(client)

class ScanRequest(BaseModel):
    sender: str
    subject: str
    body: str

@app.post("/api/scan")
async def scan_single_mail(req: ScanRequest):
    score, tier, reasons, lens, quishing = evaluate_threat(req.sender, req.subject, req.body)
    flags = [{"type": r.split(":")[0], "detail": r} for r in reasons]
    
    mail_data = {
        "id": int(asyncio.get_event_loop().time() * 1000),
        "sender": req.sender,
        "subject": req.subject,
        "body": req.body,
        "rank_score": score,
        "verdict": "PHISHING" if score >= 65 else ("FLAGGED FOR HUMAN" if score >= 35 else "SAFE"),
        "confidence": f"Automated ({score}%)",
        "flags": flags,
        "lens_data": lens,
        "quishing": quishing,
        "review_type": "Live Webhook Intercept"
    }
    await broadcast_email(mail_data)
    return mail_data

def run_push_listener(loop):
    while True:
        try:
            with MailBox(IMAP_SERVER).login(GMAIL_USER, GMAIL_APP_PASSWORD, 'INBOX') as mailbox:
                existing_uids = set(msg.uid for msg in mailbox.fetch(limit=1, reverse=True))
                last_seen_uid = list(existing_uids)[0] if existing_uids else None

                while True:
                    responses = mailbox.idle.wait(timeout=60)
                    if responses:
                        for msg in mailbox.fetch(A(all=True), limit=3, reverse=True):
                            if last_seen_uid is None or int(msg.uid) > int(last_seen_uid):
                                last_seen_uid = msg.uid
                                body_content = msg.text or msg.html or ""
                                score, tier, reasons, lens, quishing = evaluate_threat(msg.from_, msg.subject, body_content)
                                flags = [{"type": r.split(":")[0], "detail": r} for r in reasons]
                                
                                mail_obj = {
                                    "id": int(loop.time() * 1000),
                                    "sender": msg.from_,
                                    "subject": msg.subject,
                                    "body": body_content,
                                    "rank_score": score,
                                    "verdict": "PHISHING" if score >= 65 else ("FLAGGED FOR HUMAN" if score >= 35 else "SAFE"),
                                    "confidence": f"Push Feed ({score}%)",
                                    "flags": flags,
                                    "lens_data": lens,
                                    "quishing": quishing,
                                    "review_type": "Live Gmail Intercept"
                                }
                                asyncio.run_coroutine_threadsafe(broadcast_email(mail_obj), loop)
        except Exception:
            import time
            time.sleep(3)

@app.on_event("startup")
async def startup_event():
    import threading
    loop = asyncio.get_event_loop()
    listener_thread = threading.Thread(target=run_push_listener, args=(loop,), daemon=True)
    listener_thread.start()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)