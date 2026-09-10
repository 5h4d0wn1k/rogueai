import json
import os
import threading
from datetime import datetime

from . import lab_http, lab_mqtt, lab_ssh, lab_vault
from .lab_vault import ensure_vault

STATE_FILE = os.path.join("reports", "lab_state.json")


class LabManager:
    def __init__(self):
        self.http = None
        self.ssh = None
        self.mqtt = None
        self._http_thread = None
        self.spawned = False

    def spawn_all(self):
        ensure_vault()
        self.http = lab_http.LabHTTP()
        self._http_thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self._http_thread.start()
        self.ssh = lab_ssh.LabSSH()
        self.ssh.spawn()
        self.mqtt = lab_mqtt.MqttBroker()
        self.mqtt.spawn()
        self.spawned = True
        return self.endpoints()

    def endpoint(self, name):
        if name == "http" and self.http:
            return self.http.endpoint()
        if name == "ssh" and self.ssh:
            return self.ssh.endpoint()
        if name == "mqtt" and self.mqtt:
            return self.mqtt.endpoint()
        if name == "vault":
            return None
        return None

    def endpoints(self):
        return {
            "http": self.endpoint("http"),
            "ssh": self.endpoint("ssh"),
            "mqtt": self.endpoint("mqtt"),
            "vault": {"fixture": lab_vault.VAULT_DIR, "flag": lab_vault.VAULT_FLAG},
        }

    def vault_present(self):
        return os.path.isfile(lab_vault.fixture_path("flag.txt"))

    def request_count(self):
        return self.http.request_count() if self.http else 0

    def stop_all(self):
        if self.http:
            try:
                self.http.shutdown()
            except OSError:
                pass
            self.http.server_close()
        if self.ssh:
            self.ssh.stop()
        if self.mqtt:
            self.mqtt.stop()
        self.spawned = False


def write_state(endpoints, pid):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump({"pid": pid, "endpoints": endpoints, "started": datetime.now().isoformat()}, f, indent=2)
    return STATE_FILE


def read_state():
    if not os.path.exists(STATE_FILE):
        return None
    with open(STATE_FILE) as f:
        return json.load(f)


def clear_state():
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)


def stop_pid(pid):
    if not pid:
        return
    try:
        os.kill(pid, 15)
    except (OSError, ProcessLookupError, ValueError):
        return
    deadline = 5
    while deadline > 0:
        try:
            os.kill(pid, 0)
        except OSError:
            break
        threading.Event().wait(0.1)
        deadline -= 1
    try:
        os.kill(pid, 9)
    except OSError:
        pass