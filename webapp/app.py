#!/usr/bin/env python3
"""Flask webapp wrapping the sysbus Livebox CLI tool."""

import json
import os
import sys
import pickle
import tempfile
import configparser
import datetime

from flask import Flask, render_template, jsonify, request
import requests as http_requests
import requests.utils
from dateutil.tz import tz
from dateutil import parser as parsedate

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Livebox connection state
# ---------------------------------------------------------------------------

livebox = {
    "url": "http://192.168.1.1/",
    "user": "admin",
    "password": "admin",
    "version": "lb4",
    "session": None,
    "headers": None,
}


def state_file():
    return os.path.join(tempfile.gettempdir(), "sysbus_webapp_state")


def load_conf():
    """Load ~/.sysbusrc if present."""
    rc = os.path.expanduser("~/.sysbusrc")
    config = configparser.ConfigParser()
    try:
        config.read(rc)
        livebox["url"] = config["main"]["URL_LIVEBOX"]
        livebox["user"] = config["main"]["USER_LIVEBOX"]
        livebox["password"] = config["main"]["PASSWORD_LIVEBOX"]
        livebox["version"] = config["main"]["VERSION_LIVEBOX"]
    except Exception:
        pass


def auth(new_session=False):
    """Authenticate with the Livebox. Returns True on success."""
    try:
        for _ in range(2):
            if not new_session and os.path.exists(state_file()):
                with open(state_file(), "rb") as f:
                    cookies = requests.utils.cookiejar_from_dict(pickle.load(f))
                    session = http_requests.Session()
                    session.cookies = cookies
                    context_id = pickle.load(f)
            else:
                session = http_requests.Session()
                if livebox["version"] != "lb4":
                    params = {"username": livebox["user"], "password": livebox["password"]}
                    r = session.post(livebox["url"] + "authenticate", params=params, timeout=5)
                else:
                    data = (
                        '{"service":"sah.Device.Information","method":"createContext",'
                        '"parameters":{"applicationName":"so_sdkut",'
                        '"username":"%s","password":"%s"}}' % (livebox["user"], livebox["password"])
                    )
                    headers = {
                        "Content-Type": "application/x-sah-ws-1-call+json",
                        "Authorization": "X-Sah-Login",
                    }
                    r = session.post(livebox["url"] + "ws", data=data, headers=headers, timeout=5)

                resp = r.json()
                if "contextID" not in resp.get("data", {}):
                    break

                context_id = resp["data"]["contextID"]
                with open(state_file(), "wb") as f:
                    pickle.dump(requests.utils.dict_from_cookiejar(session.cookies), f, pickle.HIGHEST_PROTOCOL)
                    pickle.dump(context_id, f, pickle.HIGHEST_PROTOCOL)

            sah_headers = {
                "X-Context": context_id,
                "X-Prototype-Version": "1.7",
                "Content-Type": "application/x-sah-ws-1-call+json; charset=UTF-8",
                "Accept": "text/javascript",
            }

            # Verify auth
            r = session.post(
                livebox["url"] + "sysbus/Time:getTime",
                headers=sah_headers,
                data='{"parameters":{}}',
                timeout=5,
            )
            if r.json().get("result", {}).get("status") is True:
                livebox["session"] = session
                livebox["headers"] = sah_headers
                return True
            else:
                try:
                    os.remove(state_file())
                except OSError:
                    pass
                new_session = True
    except (http_requests.exceptions.ConnectionError,
            http_requests.exceptions.Timeout,
            Exception):
        pass

    return False


def requete(chemin, args=None, get=False):
    """Send a sysbus request to the Livebox. Returns parsed JSON or None."""
    session = livebox["session"]
    sah_headers = livebox["headers"]
    if session is None or sah_headers is None:
        return None

    c = str.replace(chemin or "sysbus", ".", "/")
    if c[0] == "/":
        c = c[1:]
    if c[:7] != "sysbus/":
        c = "sysbus/" + c

    try:
        if get:
            if args is None:
                c += "?_restDepth=-1"
            else:
                c += "?_restDepth=" + str(args)
            t = session.get(livebox["url"] + c, headers=sah_headers, timeout=10)
            t = t.content
        else:
            parameters = dict(args) if args else {}
            data = {"parameters": parameters}
            sep = c.rfind(":")
            data["service"] = c[:sep].replace("/", ".")
            if data["service"][:7] == "sysbus.":
                data["service"] = data["service"][7:]
            data["method"] = c[sep + 1 :]
            c = "ws"
            t = session.post(livebox["url"] + c, headers=sah_headers, data=json.dumps(data), timeout=10)
            t = t.content
    except (http_requests.exceptions.ConnectionError,
            http_requests.exceptions.Timeout):
        return None

    t = t.replace(b"\xf0\x44\x6e\x22", b"aaaa")
    t = t.decode("utf-8", errors="replace")

    if get and t.find("}{"):
        t = "[" + t.replace("}{", "},{") + "]"

    try:
        r = json.loads(t)
    except Exception:
        return None

    if not get and "result" in r:
        if "errors" not in r["result"]:
            return r["result"]
        return None
    return r


def ensure_auth():
    """Make sure we're authenticated. Returns error response or None."""
    if livebox["session"] is None:
        if not auth():
            return jsonify({"error": "Authentication failed. Check your Livebox settings."}), 401
    # Quick check - if session exists, verify it still works
    return None


# ---------------------------------------------------------------------------
# Routes - Pages
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Routes - API
# ---------------------------------------------------------------------------


@app.route("/api/auth", methods=["POST"])
def api_auth():
    """Authenticate (or re-authenticate) with the Livebox."""
    data = request.get_json(silent=True) or {}
    if "url" in data:
        livebox["url"] = data["url"]
        if not livebox["url"].endswith("/"):
            livebox["url"] += "/"
    if "user" in data:
        livebox["user"] = data["user"]
    if "password" in data:
        livebox["password"] = data["password"]
    if "version" in data:
        livebox["version"] = data["version"]

    try:
        os.remove(state_file())
    except OSError:
        pass

    if auth(new_session=True):
        return jsonify({"status": "ok"})
    return jsonify({"error": "Authentication failed"}), 401


@app.route("/api/info")
def api_info():
    err = ensure_auth()
    if err:
        return err
    result = requete("DeviceInfo:get")
    if result and "status" in result:
        return jsonify(result["status"])
    return jsonify({"error": "Could not get device info"}), 500


@app.route("/api/time")
def api_time():
    err = ensure_auth()
    if err:
        return err
    result = requete("Time:getTime")
    if result and "data" in result:
        tz_result = requete("Time:getLocalTimeZoneName")
        timezone = tz_result.get("data", {}).get("timezone", "unknown") if tz_result else "unknown"
        return jsonify({"time": result["data"]["time"], "timezone": timezone})
    return jsonify({"error": "Could not get time"}), 500


@app.route("/api/hosts")
def api_hosts():
    err = ensure_auth()
    if err:
        return err
    result = requete("Hosts.Host:get")
    if result and "status" in result:
        hosts = []
        for _, host in result["status"].items():
            hosts.append({
                "mac": host.get("MACAddress", ""),
                "ip": host.get("IPAddress", ""),
                "name": host.get("HostName", ""),
                "active": host.get("Active", False),
                "interface": host.get("InterfaceType", ""),
            })
        hosts.sort(key=lambda h: (not h["active"], h["name"].lower()))
        return jsonify(hosts)
    return jsonify({"error": "Could not get hosts"}), 500


@app.route("/api/wifi")
def api_wifi():
    err = ensure_auth()
    if err:
        return err
    result = requete("NeMo.Intf.data:getMIBs", {"traverse": "all"})
    if result and "status" in result and "wlanvap" in result["status"]:
        networks = []
        for wl, c in result["status"]["wlanvap"].items():
            if "BSSID" in c:
                networks.append({
                    "name": wl,
                    "bssid": c.get("BSSID", ""),
                    "ssid": c.get("SSID", ""),
                    "passphrase": c.get("Security", {}).get("KeyPassPhrase", ""),
                    "security": c.get("Security", {}).get("ModeEnabled", ""),
                })
        return jsonify(networks)
    return jsonify({"error": "Could not get WiFi info"}), 500


@app.route("/api/wifistate")
def api_wifistate():
    err = ensure_auth()
    if err:
        return err
    result = requete("NMC.Wifi:get")
    if result:
        return jsonify(result)
    return jsonify({"error": "Could not get WiFi state"}), 500


@app.route("/api/wifi/on", methods=["POST"])
def api_wifi_on():
    err = ensure_auth()
    if err:
        return err
    result = requete("NMC.Wifi:set", {"Enable": True, "Status": True})
    return jsonify(result or {"status": "ok"})


@app.route("/api/wifi/off", methods=["POST"])
def api_wifi_off():
    err = ensure_auth()
    if err:
        return err
    result = requete("NMC.Wifi:set", {"Enable": False, "Status": False})
    return jsonify(result or {"status": "ok"})


@app.route("/api/dslrate")
def api_dslrate():
    err = ensure_auth()
    if err:
        return err
    result = requete("NeMo.Intf.data:getMIBs", {"traverse": "down", "mibs": "dsl"})
    if (result and "status" in result
            and "dsl" in result["status"]
            and "dsl0" in result["status"]["dsl"]):
        m = result["status"]["dsl"]["dsl0"]
        return jsonify({
            "downstream": round(m["DownstreamCurrRate"] / 1024.0, 2),
            "upstream": round(m["UpstreamCurrRate"] / 1024.0, 2),
            "last_change": str(datetime.timedelta(seconds=int(m["LastChange"]))),
        })
    return jsonify({"error": "DSL rate not available"}), 500


@app.route("/api/dhcp")
def api_dhcp():
    err = ensure_auth()
    if err:
        return err
    if livebox["version"] == "lb28":
        obj = "NMC"
    else:
        obj = "DHCPv4.Server.Pool.default"
    result = requete(obj + ":getStaticLeases")
    if result and "status" in result:
        return jsonify(result["status"])
    return jsonify({"error": "Could not get DHCP leases"}), 500


@app.route("/api/nat")
def api_nat():
    err = ensure_auth()
    if err:
        return err
    result = requete("Firewall:getPortForwarding")
    if result and "status" in result:
        rules = []
        for name, data in result["status"].items():
            if "upnp" not in name:
                rules.append({
                    "id": data.get("Id", ""),
                    "description": data.get("Description", name),
                    "enabled": data.get("Enable", False),
                    "protocol": data.get("Protocol", ""),
                    "external_port": data.get("ExternalPort", ""),
                    "internal_port": data.get("InternalPort", ""),
                    "destination_ip": data.get("DestinationIPAddress", ""),
                    "source_interface": data.get("SourceInterface", ""),
                })
        return jsonify(rules)
    return jsonify({"error": "Could not get NAT rules"}), 500


@app.route("/api/calls")
def api_calls():
    err = ensure_auth()
    if err:
        return err
    result = requete("VoiceService.VoiceApplication:getCallList")
    if result and "status" in result:
        calls = []
        for i in result["status"]:
            try:
                start = parsedate.isoparse(i["startTime"]).astimezone(tz.tzlocal()).isoformat()
            except Exception:
                start = i.get("startTime", "")
            calls.append({
                "id": i.get("callId", ""),
                "direction": "incoming" if i.get("callOrigin") == "local" else "outgoing",
                "number": i.get("remoteNumber", ""),
                "time": start,
                "duration": str(datetime.timedelta(seconds=int(i.get("duration", 0)))),
                "type": i.get("callType", ""),
            })
        return jsonify(calls)
    return jsonify({"error": "Could not get call list"}), 500


@app.route("/api/devices")
def api_devices():
    err = ensure_auth()
    if err:
        return err
    result = requete("Devices:get")
    if result and "status" in result:
        return jsonify(result["status"])
    return jsonify({"error": "Could not get devices"}), 500


@app.route("/api/wan")
def api_wan():
    err = ensure_auth()
    if err:
        return err
    result = requete("NMC:getWANStatus")
    if result and "data" in result:
        return jsonify(result["data"])
    return jsonify({"error": "Could not get WAN status"}), 500


@app.route("/api/phone")
def api_phone():
    err = ensure_auth()
    if err:
        return err
    result = requete("VoiceService.VoiceApplication:listTrunks")
    if result and "status" in result:
        lines = []
        for trunk in result["status"]:
            for line in trunk.get("trunk_lines", []):
                lines.append({
                    "number": line.get("directoryNumber", ""),
                    "enabled": line.get("enable", "") == "Enabled",
                    "status": line.get("status", ""),
                    "name": line.get("name", ""),
                })
        return jsonify(lines)
    return jsonify({"error": "Could not get phone info"}), 500


@app.route("/api/raw", methods=["POST"])
def api_raw():
    """Execute an arbitrary sysbus request."""
    err = ensure_auth()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    path = data.get("path", "")
    params = data.get("params")
    if not path:
        return jsonify({"error": "Missing 'path'"}), 400
    result = requete(path, params)
    if result is not None:
        return jsonify(result)
    return jsonify({"error": "Request failed"}), 500


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

load_conf()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
