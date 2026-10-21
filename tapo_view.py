#!/usr/bin/env python3
"""View and pan a Tapo camera through TP-Link's cloud.

Reimplemented from the official Android app (com.tplink.iot 3.21.114):
account login is POST /api/v2/account/login, the camera list comes from
/api/v2/common/getDeviceListByPage, the relay session from
{cipc}/v2/relay/request, and video is multipart MPEG-TS on that relay.
Pan and tilt go to the IoT app server as a passthrough, and only when the
camera reports a ptz component.

The password is read from a hidden prompt unless --password is passed.
A successful login is saved and reused until the server rejects the token.
This talks to cameras on the account you log in with.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter

APP_TYPE = "TP-Link_Tapo_Android"
APP_VERSION = "3.21.114"
ACCESS_KEY = "e37525375f8845999bcc56d5e6faa76d"
SECRET = "314bc6700b3140ca80bc655e527cb062"
GATEWAY = "https://n-wap.i.tplinkcloud.com"
SIGN_TIMESTAMP = "9999999999"
CLIENT_BOUNDARY = "----client-stream-boundary--"
DEVICE_BOUNDARY = b"----device-stream-boundary--"
# TP-Link Cloud Root CA, extracted from the Tapo app. The relay hosts are not
# signed by a public CA, so this root is trusted in addition to the system store.
TAPO_CLOUD_ROOT = """-----BEGIN CERTIFICATE-----
MIICKTCCAdCgAwIBAgIUXZHoRKIvheKCxJL4s2rZ/alfEGMwCgYIKoZIzj0EAwMw
cjEeMBwGA1UEAwwVVFAtTGluayBDbG91ZCBSb290IENBMR0wGwYDVQQKDBRUUC1M
aW5rIFN5c3RlbXMgSW5jLjEPMA0GA1UEBwwGSXJ2aW5lMRMwEQYDVQQIDApDYWxp
Zm9ybmlhMQswCQYDVQQGEwJVUzAgFw0yNTAyMjUwMzQ3MTFaGA8yMDU1MDIxODAz
NDcxMVowcjEeMBwGA1UEAwwVVFAtTGluayBDbG91ZCBSb290IENBMR0wGwYDVQQK
DBRUUC1MaW5rIFN5c3RlbXMgSW5jLjEPMA0GA1UEBwwGSXJ2aW5lMRMwEQYDVQQI
DApDYWxpZm9ybmlhMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABAHpyZzXk1E4VWyIB+9VMci2Sw5OdeQ+kyFc2/R/f/OiHt6hk4PfMcCKKgS6
hkVVYyVlobJNn052z+s9DJKJgfajQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P
AQH/BAQDAgGGMB0GA1UdDgQWBBQLV0PTee1jvnJMcUCEtQgJSg/oyTAKBggqhkjO
PQQDAwNHADBEAiAURU4PvHXUrVViDF+rCky3RD9BeUpe91kYoNWe0oKVUwIgY0C5
MsDHbQrwLHs1I7+f2MvZDGBHhNjnl0n4MF9q0L0=
-----END CERTIFICATE-----
"""


class _CloudTLS(HTTPAdapter):
    """Trust the public CAs plus the TP-Link Cloud Root CA shipped in the app."""

    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        kwargs["ssl_context"] = cloud_ssl_context()
        return super().init_poolmanager(connections, maxsize, block, **kwargs)


def cloud_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.load_verify_locations(cadata=TAPO_CLOUD_ROOT)
    return context


SESSION = requests.Session()
SESSION.mount("https://", _CloudTLS())


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def content_md5(body: bytes) -> str:
    digest = hashlib.md5(body).digest()
    return base64.b64encode(digest).decode()


def sign(path: str, body: bytes, nonce: str) -> tuple[str, str]:
    md5 = content_md5(body)
    material = f"{md5}\n{SIGN_TIMESTAMP}\n{nonce}\n{path}"
    signature = hmac.new(SECRET.encode(), material.encode(), hashlib.sha1).hexdigest()
    authorization = (
        f"Timestamp={SIGN_TIMESTAMP}, Nonce={nonce}, "
        f"AccessKey={ACCESS_KEY}, Signature={signature}"
    )
    return md5, authorization


def api(base: str, path: str, payload: dict, token: str | None = None) -> dict:
    body = json.dumps(payload, separators=(",", ":")).encode()
    nonce = str(uuid.uuid4())
    md5, authorization = sign(path, body, nonce)
    params = {
        "appName": APP_TYPE,
        "appVer": APP_VERSION,
        "netType": "wifi",
        "termID": str(uuid.uuid4()),
        "ospf": "Android 14",
        "brand": "TPLINK",
        "locale": "en_US",
        "model": "cli",
        "termName": "tapo-cli",
    }
    if token:
        params["token"] = token
    url = base.rstrip("/") + path
    response = SESSION.post(
        url,
        params=params,
        data=body,
        headers={
            "Content-Type": "application/json;charset=UTF-8",
            "Content-MD5": md5,
            "X-Authorization": authorization,
        },
        timeout=30,
    )
    try:
        data = response.json()
    except ValueError as exc:
        raise SystemExit(f"{path} returned {response.status_code}: {response.text[:400]}") from exc
    return data


def normalize_url(url: str) -> str:
    if url.startswith("http://") or url.startswith("https://"):
        return url.rstrip("/")
    return "https://" + url.rstrip("/")


# LoginV2Result.errorCode when two-step verification is on. The app then
# calls getPushVC4TerminalMFA and finishes with checkMFACodeAndLogin.
MFA_REQUIRED = -20677
MFA_PUSH = 1
MFA_EMAIL = 2


def result_error(data: dict) -> tuple[int, str]:
    result = data.get("result")
    if not isinstance(result, dict):
        return 0, ""
    raw = result.get("errorCode")
    message = str(result.get("errorMsg") or "")
    if raw in (None, "", 0, "0"):
        return 0, message
    try:
        return int(raw), message
    except (TypeError, ValueError):
        return -1, message or str(raw)


def raise_if_failed(data: dict, what: str) -> None:
    if data.get("error_code", 0) not in (0, None):
        raise SystemExit(f"{what} failed: {data.get('msg') or data.get('error_code')}")
    code, message = result_error(data)
    if code != 0:
        detail = f"{message} ({code})" if message else str(code)
        raise SystemExit(f"{what} failed: {detail}")


class SessionExpired(Exception):
    pass


def config_dir() -> Path:
    return Path.home() / ".config" / "tapo-cli"


def terminal_uuid() -> str:
    path = config_dir() / "terminal-uuid"
    if path.is_file():
        saved = path.read_text().strip()
        if saved:
            return saved
    path.parent.mkdir(parents=True, exist_ok=True)
    saved = str(uuid.uuid4())
    path.write_text(saved + "\n")
    path.chmod(0o600)
    return saved


def send_mfa_code(base: str, email: str, password: str, terminal: str) -> int:
    body = {
        "cloudUserName": email,
        "cloudPassword": password,
        "appType": APP_TYPE,
        "terminalUUID": terminal,
    }
    pushed = api(base, "/api/v2/account/getPushVC4TerminalMFA", body)
    if pushed.get("error_code", 0) in (0, None):
        log("Verification code sent to the Tapo app on a device that is already signed in.")
        return MFA_PUSH
    mailed = api(base, "/api/v2/account/getEmailVC4TerminalMFA", {**body, "locale": "en_US"})
    if mailed.get("error_code", 0) in (0, None):
        log("Verification code sent by email.")
        return MFA_EMAIL
    push_msg = pushed.get("msg") or pushed.get("error_code")
    mail_msg = mailed.get("msg") or mailed.get("error_code")
    raise SystemExit(f"could not send a verification code: app notification {push_msg}; email {mail_msg}")


def login(email: str, password: str, mfa_code: str | None) -> tuple[str, str]:
    status = api(
        GATEWAY,
        "/api/v2/account/getAccountStatusAndUrl",
        {"cloudUserName": email, "appType": APP_TYPE},
    )
    raise_if_failed(status, "account lookup")
    result = status.get("result") or {}
    base = normalize_url(result.get("appServerUrlV2") or result.get("appServerUrl") or GATEWAY)
    log(f"account server {base}")
    terminal = terminal_uuid()
    # Same fields TCAccountRepository.J1 sends. terminalMeta is required;
    # omitting it makes the server return -20104 "Parameter doesn't exist".
    logged = api(
        base,
        "/api/v2/account/login",
        {
            "cloudUserName": email,
            "cloudPassword": password,
            "appType": APP_TYPE,
            "terminalUUID": terminal,
            "terminalName": "tapo-cli",
            "terminalMeta": "1",
            "platform": "Android 14",
            "appVersion": APP_VERSION,
            "refreshTokenNeeded": False,
        },
    )
    if logged.get("error_code", 0) not in (0, None):
        raise SystemExit(f"login failed: {logged.get('msg') or logged.get('error_code')}")
    info = logged.get("result") or {}
    code, message = result_error(logged)
    process_id = info.get("MFAProcessId") or info.get("mfaProcessId")
    if code == MFA_REQUIRED or process_id:
        if not process_id:
            detail = f"{message} ({code})" if message else str(code)
            raise SystemExit(f"login failed: {detail}")
        mfa_type = send_mfa_code(base, email, password, terminal)
        if not mfa_code:
            if not sys.stdin.isatty():
                raise SystemExit("verification code required; pass --mfa CODE")
            mfa_code = input("Verification code: ").strip()
        if not mfa_code:
            raise SystemExit("verification code is empty")
        logged = api(
            base,
            "/api/v2/account/checkMFACodeAndLogin",
            {
                "cloudUserName": email,
                "appType": APP_TYPE,
                "code": mfa_code,
                "MFAProcessId": process_id,
                "MFAType": mfa_type,
                "terminalBindEnabled": True,
            },
        )
        raise_if_failed(logged, "verification")
        info = logged.get("result") or {}
    elif code != 0:
        detail = f"{message} ({code})" if message else str(code)
        raise SystemExit(f"login failed: {detail}")
    token = info.get("token")
    if not token:
        raise SystemExit(f"login did not return a token: {logged}")
    return base, token


def load_session(email: str) -> dict | None:
    path = config_dir() / "session.json"
    try:
        saved = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not saved.get("email") or not saved.get("base") or not saved.get("token"):
        return None
    if email and saved["email"].lower() != email.lower():
        return None
    return saved


def save_session(email: str, base: str, token: str) -> None:
    path = config_dir() / "session.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"email": email, "base": base, "token": token}))
    path.chmod(0o600)


def clear_session() -> None:
    try:
        (config_dir() / "session.json").unlink()
    except FileNotFoundError:
        pass


def token_ok(base: str, email: str, token: str) -> bool:
    checked = api(base, "/api/v2/account/login", {"cloudUserName": email}, token)
    return checked.get("error_code", 0) in (0, None) and result_error(checked)[0] == 0


def open_session(email: str, password: str | None, mfa_code: str | None) -> tuple[str, str, str]:
    saved = load_session(email)
    if saved and token_ok(saved["base"], saved["email"], saved["token"]):
        log("using saved session")
        return saved["email"], saved["base"], saved["token"]
    if saved:
        log("saved session expired")
        clear_session()
        email = email or saved["email"]
    if not email:
        raise SystemExit("set TAPO_EMAIL or pass --email")
    if not password:
        password = getpass.getpass("Tapo password: ")
    if not password:
        raise SystemExit("password is empty")
    base, token = login(email, password, mfa_code)
    save_session(email, base, token)
    return email, base, token


def cameras(base: str, token: str) -> list[dict]:
    found: list[dict] = []
    index = 0
    total = None
    while total is None or index < total:
        page = api(
            base,
            "/api/v2/common/getDeviceListByPage",
            {"index": index, "limit": 20, "deviceTypeList": ["SMART.IPCAMERA"]},
            token,
        )
        if page.get("error_code", 0) in (-20651, -20675):
            raise SessionExpired(page.get("msg") or "token expired")
        if page.get("error_code", 0) != 0:
            raise SystemExit(f"device list failed: {page}")
        result = page.get("result") or {}
        batch = result.get("deviceList") or []
        found.extend(batch)
        total = result.get("totalNum", len(found))
        if not batch:
            break
        index += len(batch)
    return found


def choose_camera(devices: list[dict], name: str | None, device_id: str | None) -> dict:
    if device_id:
        for device in devices:
            if device.get("deviceId") == device_id:
                return device
        raise SystemExit(f"no camera with deviceId {device_id}")
    if name:
        matches = [
            device
            for device in devices
            if name.lower() in (device.get("alias") or "").lower()
            or name.lower() in (device.get("deviceName") or "").lower()
        ]
        if len(matches) == 1:
            return matches[0]
        raise SystemExit(f"{len(matches)} cameras match {name!r}")
    if len(devices) == 1:
        return devices[0]
    raise SystemExit("more than one camera; pass --name or --id")


def service_url(base: str, token: str, service_id: str) -> str:
    data = api(
        base,
        "/api/v2/common/getAppServiceUrl",
        {"serviceIds": [service_id]},
        token,
    )
    if data.get("error_code", 0) != 0:
        raise SystemExit(f"service url failed: {data.get('msg') or data.get('error_code')}")
    urls = (data.get("result") or {}).get("serviceUrls") or {}
    url = urls.get(service_id)
    if not url:
        raise SystemExit(f"no {service_id} url")
    return normalize_url(url)


def cipc_url(base: str, token: str) -> str:
    return service_url(base, token, "cipc.api.cloud")


def iot_headers(token: str) -> dict[str, str]:
    # The thing cloud wants the account token as "ut|<token>" and app-cid as
    # "app:<app type>:<terminal uuid>". A bare token is rejected as a bad format.
    term = terminal_uuid()
    return {
        "Authorization": f"ut|{token}",
        "app-cid": f"app:{APP_TYPE}:{term}",
        "x-app-name": APP_TYPE,
        "x-app-version": APP_VERSION,
        "x-term-id": term,
        "x-ospf": "Android 14",
        "x-net-type": "wifi",
        "x-strict": "0",
        "x-locale": "en_US",
    }


def thing_components(app: str, token: str, device_id: str) -> set[str]:
    response = SESSION.get(
        f"{app}/v1/things/{device_id}/components",
        headers=iot_headers(token),
        timeout=30,
    )
    try:
        data = response.json()
    except ValueError as exc:
        raise SystemExit(f"component list failed: HTTP {response.status_code}") from exc
    if response.status_code != 200:
        raise SystemExit(f"component list failed: {data.get('message') or response.status_code}")
    found = set()
    for item in data.get("component_list") or []:
        if isinstance(item, dict) and item.get("id"):
            found.add(str(item["id"]))
    return found


def camera_request(app: str, token: str, device_id: str, method: str, params: dict) -> dict:
    # The app wraps one camera call in multipleRequest, then posts it as the
    # passthrough service on the IoT app server. services-sync returns the
    # camera's reply; the plain services path only returns a request id.
    body = {
        "serviceId": "passthrough",
        "inputParams": {
            "requestData": {
                "method": "multipleRequest",
                "params": {"requests": [{"method": method, "params": params}]},
            }
        },
    }
    response = SESSION.post(
        f"{app}/v1/things/{device_id}/services-sync",
        headers={**iot_headers(token), "Content-Type": "application/json;charset=UTF-8"},
        data=json.dumps(body, separators=(",", ":")).encode(),
        timeout=30,
    )
    try:
        data = response.json()
    except ValueError as exc:
        raise SystemExit(f"{method} failed: HTTP {response.status_code}") from exc
    if response.status_code != 200:
        raise SystemExit(f"{method} failed: {data.get('message') or response.status_code}")
    output = (data.get("outputParams") or {}).get("responseData") or {}
    result = output.get("result") if isinstance(output, dict) else None
    responses = result.get("responses") if isinstance(result, dict) else None
    if not responses:
        raise SystemExit(f"{method} failed")
    item = responses[0]
    code = item.get("error_code", 0)
    if code not in (0, None):
        raise SystemExit(f"camera rejected {method}: {code}")
    payload = item.get("result")
    return payload if isinstance(payload, dict) else {}


# Positive x is right and positive y is up, the same axes motorMove uses.
PTZ_STEPS = {
    "left": (-1, 0),
    "right": (1, 0),
    "up": (0, 1),
    "down": (0, -1),
}
PTZ_ACTIONS = ("left", "right", "up", "down", "stop", "presets", "goto", "cruise", "cruise-stop")


def preset_rows(result: dict) -> list[tuple[str, str]]:
    preset = (result.get("preset") or {}).get("preset")
    if isinstance(preset, list):
        rows = []
        for item in preset:
            if isinstance(item, dict):
                rows.append((str(item.get("id", "")), str(item.get("name", ""))))
        return rows
    if isinstance(preset, dict):
        ids = preset.get("id") or []
        names = preset.get("name") or []
        if isinstance(ids, list):
            rows = []
            for index, ident in enumerate(ids):
                name = names[index] if isinstance(names, list) and index < len(names) else ""
                rows.append((str(ident), str(name)))
            return rows
    return []


def run_ptz(base: str, token: str, devices: list[dict], args: argparse.Namespace) -> None:
    action = args.action
    if action not in PTZ_ACTIONS:
        names = ", ".join(PTZ_ACTIONS)
        raise SystemExit(f"ptz action must be one of: {names}")
    if action in ("goto", "cruise") and not args.target:
        raise SystemExit(f"ptz {action} needs a value")
    if action not in ("goto", "cruise") and args.target:
        raise SystemExit(f"ptz {action} does not take a value")
    device = choose_camera(devices, args.name, args.id)
    alias = device.get("alias") or device.get("deviceName") or device.get("deviceModel") or "camera"
    app = service_url(base, token, "nbu.iot-app-server.app-v2")
    components = thing_components(app, token, device["deviceId"])
    if "ptz" not in components:
        raise SystemExit(f"{alias} does not support pan and tilt")
    device_id = device["deviceId"]
    if action in PTZ_STEPS:
        if args.step <= 0:
            raise SystemExit("--step must be a positive number")
        sx, sy = PTZ_STEPS[action]
        camera_request(
            app,
            token,
            device_id,
            "motorMove",
            {"motor": {"move": {"x_coord": str(sx * args.step), "y_coord": str(sy * args.step)}}},
        )
        log(f"moved {alias} {action} by {args.step}")
        return
    if action == "stop":
        camera_request(app, token, device_id, "stopMove", {"motor": {"stop": "null"}})
        log(f"stopped {alias}")
        return
    if action == "presets":
        rows = preset_rows(camera_request(
            app,
            token,
            device_id,
            "getPresetConfig",
            {"preset": {"name": ["preset"]}},
        ))
        if not rows:
            log(f"{alias} has no presets")
            return
        for ident, name in rows:
            print(f"{ident}\t{name}")
        return
    if action == "goto":
        camera_request(
            app,
            token,
            device_id,
            "motorMoveToPreset",
            {"preset": {"goto_preset": {"id": str(args.target)}}},
        )
        log(f"moved {alias} to preset {args.target}")
        return
    if action == "cruise":
        axis = args.target
        if axis not in ("x", "y"):
            raise SystemExit("ptz cruise needs x (pan) or y (tilt)")
        camera_request(
            app,
            token,
            device_id,
            "cruiseMove",
            {"motor": {"cruise": {"coord": axis}}},
        )
        log(f"{alias} cruising on {axis}; ptz cruise-stop to end it")
        return
    camera_request(app, token, device_id, "cruiseStop", {"motor": {"cruise_stop": "null"}})
    log(f"stopped cruise on {alias}")


def request_relay(cipc: str, token: str, device: dict, resolution: str) -> dict:
    player = terminal_uuid()
    payload = {
        "deviceId": device["deviceId"],
        "playerId": player,
        "cloudType": 2,
        "deviceType": device.get("deviceType") or "SMART.IPCAMERA",
        "rootCaVer": "1",
        "preConnection": 0,
        "resolution": resolution,
        "streamType": 0,
        "dataTimeoutCount": 0,
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    signature = uuid.uuid4().hex[:10]
    response = SESSION.post(
        cipc.rstrip("/") + "/v2/relay/request",
        data=body,
        headers={
            "Content-Type": "application/json;charset=UTF-8",
            "Authorization": token,
            "User-Agent": f"Tapo_APP/cli/{APP_VERSION}_Android/Android 14",
            "X-Request-Signature": signature,
            "X-Client-Id": player,
            "X-Source": "tapo-app",
            "X-Brand": "TPLINK",
            "X-Ca-Type": "cloud-self",
            "Accept": "*/*",
        },
        timeout=30,
    )
    data = response.json()
    if data.get("errorCode", data.get("error_code", 0)) != 0:
        raise SystemExit(f"relay request failed: {data}")
    result = data.get("result") or data
    relay = result.get("relayUrl") or ""
    if not relay:
        raise SystemExit(f"relay response has no relayUrl: {data}")
    return result


def split_relay(relay_url: str) -> tuple[str, int, str]:
    raw = relay_url if "://" in relay_url else "https://" + relay_url
    parts = urlsplit(raw)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme != "http" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    if not host:
        raise SystemExit(f"relay URL has no host: {relay_url}")
    return host, port, path


def multipart_part(payload: str, extra_headers: dict[str, str] | None = None) -> bytes:
    raw = payload.encode()
    lines = [
        CLIENT_BOUNDARY,
        "Content-Type: application/json",
        f"Content-Length: {len(raw)}",
    ]
    for key, value in (extra_headers or {}).items():
        lines.append(f"{key}: {value}")
    text = "\r\n".join(lines) + "\r\n\r\n" + payload + "\r\n"
    return text.encode()


def microphone(base: str, token: str, device: dict) -> tuple[str, int, int]:
    # The relay already carries the mic as a private MPEG-TS track. The camera
    # tells us the codec: these models send G.711, which ffplay can play raw.
    alias = device.get("alias") or device.get("deviceModel") or "camera"
    app = service_url(base, token, "nbu.iot-app-server.app-v2")
    if "audio" not in thing_components(app, token, device["deviceId"]):
        raise SystemExit(f"{alias} does not support audio")
    result = camera_request(
        app,
        token,
        device["deviceId"],
        "getAudioConfig",
        {
            "audio_config": {"name": ["speaker", "microphone"]},
            "audio_capability": {"name": ["device_microphone"]},
        },
    )
    mic = ((result.get("audio_config") or {}).get("microphone") or {})
    formats = {"G711alaw": "alaw", "G711ulaw": "mulaw"}
    encode = str(mic.get("encode_type") or "")
    fmt = formats.get(encode)
    if not fmt:
        raise SystemExit(f"{alias} audio codec {encode or 'unknown'} cannot be played")
    try:
        rate = int(str(mic.get("sampling_rate") or "8"))
    except ValueError:
        rate = 8
    if rate < 1000:
        rate *= 1000
    try:
        channels = int(str(mic.get("channels") or "1"))
    except ValueError:
        channels = 1
    if mic.get("mute") == "on":
        log(f"{alias} microphone is muted")
    if str(mic.get("volume") or "0") in ("0", "0.0"):
        log(f"{alias} microphone volume is 0, so the stream may be silent")
    return fmt, rate, channels


def preview_payload(resolution: str) -> str:
    return json.dumps(
        {
            "type": "request",
            "seq": 1,
            "params": {
                "method": "get",
                "preview": {
                    "channels": [0],
                    "resolutions": [resolution],
                    "audio": ["default"],
                },
            },
        },
        separators=(",", ":"),
    )


def relay_headers(host: str, port: int, path: str, relay: dict, client_uuid: str) -> bytes:
    token = relay.get("relayToken") or relay.get("sessionToken") or ""
    cookie = relay.get("elbCookie") or ""
    lines = [
        f"POST {path} HTTP/1.1",
        f"User-Agent: Client={APP_TYPE} Android {APP_VERSION}/1.3",
        "Keep-Relay: 3600",
        "Accept: */*",
        "Content-Type: multipart/mixed;boundary=--client-stream-boundary--",
        f"Host: {host}",
        "Content-Length: 9223372036854775807",
        f"X-token: {token}",
        "X-Client-Model: cli",
        f"X-Client-UUID: {client_uuid}",
        "X-Redirect-Times: 0",
        "X-Pull-Mode: 2",
        "X-Version: 2.0",
        "X-Arrive-Latency: 0",
    ]
    session = relay.get("sessionToken")
    if session and session != token:
        lines.append(f"X-Client-SessionID: {session}")
    if cookie:
        lines.append(f"Cookie: {cookie}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


class MpegTsWriter:
    def __init__(self, play: bool, audio: tuple[str, int, int] | None = None, rewrite_sei: bool = False) -> None:
        self.play = play
        self.rewrite_sei = rewrite_sei
        self.process: subprocess.Popen[bytes] | None = None
        self.audio_process: subprocess.Popen[bytes] | None = None
        self.failed = False
        self._ts = b""
        self._pes = b""
        self._audio_pid: int | None = None
        self._sei_rest = b""
        self._sei_carry = b""
        self._video_pid: int | None = None
        if play:
            # A short probe opens the window as soon as the first frames arrive.
            # The camera's timestamps start far from zero, so sync to video.
            # Its microphone is a private stream type, pulled out separately.
            self.process = subprocess.Popen(
                [
                    "ffplay",
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-fflags",
                    "nobuffer",
                    "-flags",
                    "low_delay",
                    "-probesize",
                    "32768",
                    "-analyzeduration",
                    "0",
                    "-framedrop",
                    "-sync",
                    "video",
                    "-f",
                    "mpegts",
                    "-i",
                    "pipe:0",
                ],
                stdin=subprocess.PIPE,
            )
        if audio is not None:
            fmt, rate, channels = audio
            layout = "mono" if channels == 1 else "stereo"
            self.audio_process = subprocess.Popen(
                [
                    "ffplay",
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-nodisp",
                    "-fflags",
                    "nobuffer",
                    "-flags",
                    "low_delay",
                    "-probesize",
                    "32",
                    "-analyzeduration",
                    "0",
                    "-f",
                    fmt,
                    "-sample_rate",
                    str(rate),
                    "-ch_layout",
                    layout,
                    "-i",
                    "pipe:0",
                ],
                stdin=subprocess.PIPE,
            )

    def write(self, data: bytes) -> None:
        if self.failed:
            return
        if self.audio_process is not None:
            self._demux_audio(data)
        # Some cameras put a private SEI in every H.264 frame. libavcodec logs
        # the short payload as an error. Filler NALs are skipped, and the picture
        # does not use this SEI. Off unless --rewrite-sei is set.
        if self.rewrite_sei:
            data = self._silence_sei(data)
        self._write_out(data)

    def _write_out(self, data: bytes) -> None:
        if not data or self.failed:
            return
        if self.process is not None and self.process.stdin is not None:
            try:
                self.process.stdin.write(data)
                self.process.stdin.flush()
            except BrokenPipeError:
                self.failed = True
            return
        try:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        except BrokenPipeError:
            self.failed = True

    def _silence_sei(self, data: bytes) -> bytes:
        blob = self._sei_rest + data
        whole = len(blob) - (len(blob) % 188)
        self._sei_rest = blob[whole:]
        if whole == 0:
            return b""
        out = bytearray(blob[:whole])
        for at in range(0, whole, 188):
            packet = out[at : at + 188]
            if packet[0] != 0x47:
                continue
            pid = ((packet[1] & 0x1F) << 8) | packet[2]
            start = bool(packet[1] & 0x40)
            adapt = (packet[3] >> 4) & 0x3
            offset = 4
            if adapt & 0x2:
                if offset >= len(packet):
                    continue
                offset += 1 + packet[4]
            if offset > len(packet):
                continue
            if self._video_pid is None:
                body = bytes(packet[offset:])
                if start and len(body) >= 4 and body.startswith(b"\x00\x00\x01") and 0xE0 <= body[3] <= 0xEF:
                    self._video_pid = pid
                else:
                    continue
            if pid != self._video_pid:
                continue
            payload = bytes(out[at + offset : at + 188])
            merged = self._sei_carry + payload
            carry_len = len(self._sei_carry)
            index = 0
            while True:
                found = merged.find(b"\x00\x00\x01", index)
                if found < 0:
                    break
                header_at = found + 3
                if header_at >= carry_len and header_at < len(merged):
                    header = merged[header_at]
                    if header & 0x1F == 6:
                        out[at + offset + header_at - carry_len] = (header & 0xE0) | 12
                index = found + 3
            self._sei_carry = merged[-3:] if len(merged) >= 3 else merged
        return bytes(out)

    def _demux_audio(self, data: bytes) -> None:
        self._ts += data
        while len(self._ts) >= 188:
            if self._ts[0] != 0x47:
                sync = self._ts.find(b"\x47", 1)
                self._ts = b"" if sync < 0 else self._ts[sync:]
                continue
            packet, self._ts = self._ts[:188], self._ts[188:]
            pid = ((packet[1] & 0x1F) << 8) | packet[2]
            start = bool(packet[1] & 0x40)
            adapt = (packet[3] >> 4) & 0x3
            offset = 4
            if adapt & 0x2:
                if offset >= len(packet):
                    continue
                offset += 1 + packet[4]
            if offset > len(packet):
                continue
            body = packet[offset:]
            if self._audio_pid is None:
                if start and len(body) >= 4 and body.startswith(b"\x00\x00\x01") and 0xC0 <= body[3] <= 0xDF:
                    self._audio_pid = pid
                else:
                    continue
            if pid != self._audio_pid:
                continue
            if start:
                self._flush_audio()
            self._pes += body

    def _flush_audio(self) -> None:
        pes, self._pes = self._pes, b""
        if len(pes) < 9 or not pes.startswith(b"\x00\x00\x01"):
            return
        header = pes[8]
        payload = pes[9 + header :]
        process = self.audio_process
        if not payload or process is None or process.stdin is None:
            return
        try:
            process.stdin.write(payload)
            process.stdin.flush()
        except BrokenPipeError:
            self.audio_process = None

    def close(self) -> None:
        self._flush_audio()
        tail = self._sei_rest
        self._sei_rest = b""
        if tail and not self.failed:
            self._write_out(tail)
        for process in (self.process, self.audio_process):
            if process is None or process.stdin is None:
                continue
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
            process.wait()


def read_http_head(sock: ssl.SSLSocket) -> tuple[int, dict[str, str], bytes]:
    blob = b""
    while b"\r\n\r\n" not in blob:
        chunk = sock.recv(4096)
        if not chunk:
            break
        blob += chunk
        if len(blob) > 1024 * 1024:
            break
    head, _, rest = blob.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1", "replace").split("\r\n")
    status = 0
    if lines and len(lines[0].split()) >= 2 and lines[0].split()[1].isdigit():
        status = int(lines[0].split()[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return status, headers, rest


def stream_relay(relay: dict, resolution: str, output: MpegTsWriter) -> None:
    host, port, path = split_relay(relay["relayUrl"])
    log(f"relay {host}:{port}{path}")
    context = cloud_ssl_context()
    raw = socket.create_connection((host, port), timeout=20)
    sock = context.wrap_socket(raw, server_hostname=host)
    sock.settimeout(20)
    sock.sendall(relay_headers(host, port, path, relay, terminal_uuid()))
    status, headers, pending = read_http_head(sock)
    log(f"relay HTTP {status}")
    if status != 200:
        raise SystemExit(f"relay rejected the session: {status} {headers} {pending[:300]!r}")
    send_lock = threading.Lock()

    def send(payload: bytes) -> None:
        with send_lock:
            sock.sendall(payload)

    send(multipart_part(preview_payload(resolution), {"X-Data-Window-Size": "50"}))
    stop = threading.Event()

    def heartbeats() -> None:
        note = json.dumps(
            {"type": "notification", "params": {"event_type": "heartbeat"}},
            separators=(",", ":"),
        )
        while not stop.wait(20):
            try:
                send(multipart_part(note))
            except OSError:
                return

    threading.Thread(target=heartbeats, daemon=True).start()
    sock.settimeout(30)
    buffer = pending
    video_bytes = 0
    session_id = ""
    try:
        while not output.failed:
            while True:
                start = buffer.find(DEVICE_BOUNDARY)
                if start < 0:
                    break
                after = buffer[start + len(DEVICE_BOUNDARY) :]
                if after.startswith(b"--"):
                    return
                header_end = after.find(b"\r\n\r\n")
                if header_end < 0:
                    break
                header_blob = after[:header_end].decode("iso-8859-1", "replace")
                part_headers: dict[str, str] = {}
                for line in header_blob.split("\r\n"):
                    if ":" in line:
                        key, value = line.split(":", 1)
                        part_headers[key.strip().lower()] = value.strip()
                try:
                    length = int(part_headers.get("content-length") or "0")
                except ValueError:
                    length = 0
                body_at = header_end + 4
                if len(after) < body_at + length:
                    break
                body = after[body_at : body_at + length]
                buffer = after[body_at + length :]
                kind = part_headers.get("content-type", "")
                session_id = part_headers.get("x-session-id") or session_id
                if kind == "video/mp2t" and body:
                    output.write(body)
                    video_bytes += len(body)
                    if video_bytes == len(body):
                        log("receiving video")
                    sequence = part_headers.get("x-data-sequence")
                    if session_id and sequence and sequence.isdigit() and int(sequence) % 25 == 0:
                        send(
                            multipart_part(
                                '{"type":"notification","params":{"event_type":"stream_sequence"}}',
                                {"X-Data-Received": sequence, "X-Session-Id": session_id},
                            )
                        )
                elif kind == "application/json" and body:
                    text = body.decode("utf-8", "replace")
                    log("camera: " + text[:500])
                    try:
                        message = json.loads(text)
                    except json.JSONDecodeError:
                        message = {}
                    params = message.get("params") if isinstance(message, dict) else None
                    if isinstance(params, dict) and params.get("session_id"):
                        session_id = str(params["session_id"])
            try:
                chunk = sock.recv(65536)
            except socket.timeout as exc:
                raise SystemExit("relay went quiet for 30s") from exc
            if not chunk:
                log("relay closed")
                return
            buffer += chunk
    finally:
        stop.set()
        sock.close()
        log(f"wrote {video_bytes} bytes of MPEG-TS")


def main() -> None:
    parser = argparse.ArgumentParser(description="Play a Tapo cloud live stream, or pan and tilt a camera that supports it")
    parser.add_argument("command", choices=("list", "play", "ptz"))
    parser.add_argument("action", nargs="?", help="ptz: left, right, up, down, stop, presets, goto, cruise, cruise-stop")
    parser.add_argument("target", nargs="?", help="preset id for goto, or x/y for cruise")
    parser.add_argument("--email", default=os.environ.get("TAPO_EMAIL", ""), help="account email; remembered with the session")
    parser.add_argument("--password", help="omit this to type the password at a hidden prompt; skipped while the saved session is valid")
    parser.add_argument("--name", help="camera alias substring")
    parser.add_argument("--id", help="camera deviceId")
    parser.add_argument("--resolution", choices=("HD", "VGA"), default="HD")
    parser.add_argument("--step", type=int, default=10, help="pan/tilt distance for left, right, up, and down")
    parser.add_argument("--detailed", action="store_true", help="with list, add a column for whether the camera can pan and tilt")
    parser.add_argument("--audio", action="store_true", help="with play, also play the camera microphone when the camera supports it")
    parser.add_argument("--rewrite-sei", action="store_true", help="with play, rewrite the camera's private H.264 SEI so ffplay does not log a truncation error per frame")
    parser.add_argument("--mfa", help="two-step code; if omitted, you are prompted after it is sent")
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="write MPEG-TS to stdout instead of launching ffplay",
    )
    args = parser.parse_args()
    if args.command != "ptz" and (args.action or args.target):
        parser.error("extra arguments are only used with ptz")
    if args.detailed and args.command != "list":
        parser.error("--detailed is only used with list")
    if args.audio and args.command != "play":
        parser.error("--audio is only used with play")
    if args.rewrite_sei and args.command != "play":
        parser.error("--rewrite-sei is only used with play")
    if args.audio and args.stdout:
        parser.error("--audio plays through ffplay; leave out --stdout")
    try:
        _email, base, token = open_session(args.email, args.password, args.mfa)
        devices = cameras(base, token)
    except SessionExpired:
        clear_session()
        log("saved session expired")
        _email, base, token = open_session(args.email, args.password, args.mfa)
        devices = cameras(base, token)
    if args.command == "list":
        if not devices:
            log("no cameras on this account")
            return
        ptz_of: dict[str, bool | None] | None = None
        if args.detailed:
            app = service_url(base, token, "nbu.iot-app-server.app-v2")
            ptz_of = {}
            for device in devices:
                device_id = str(device.get("deviceId") or "")
                label = device.get("alias") or device.get("deviceModel") or "camera"
                try:
                    ptz_of[device_id] = "ptz" in thing_components(app, token, device_id)
                except SystemExit as exc:
                    log(f"{label}: {exc}")
                    ptz_of[device_id] = None
        header = "deviceId\tmodel\talias"
        if ptz_of is not None:
            header += "\tptz"
        print(header)
        for device in devices:
            alias = device.get("alias") or device.get("deviceName") or ""
            row = f"{device.get('deviceId')}\t{device.get('deviceModel') or ''}\t{alias}"
            if ptz_of is not None:
                cell = {True: "yes", False: "no"}.get(ptz_of.get(str(device.get("deviceId") or "")), "?")
                row += f"\t{cell}"
            print(row)
        return
    if args.command == "ptz":
        run_ptz(base, token, devices, args)
        return

    device = choose_camera(devices, args.name, args.id)
    alias = device.get("alias") or device.get("deviceName") or device["deviceId"]
    log(f"camera {alias} ({device.get('deviceModel')})")
    relay = request_relay(cipc_url(base, token), token, device, args.resolution)
    play = not args.stdout and sys.stdout.isatty()
    if play and shutil.which("ffplay") is None:
        raise SystemExit("ffplay is not installed; re-run with --stdout and pipe it yourself")
    audio = None
    if args.audio:
        audio = microphone(base, token, device)
        log(f"playing microphone ({audio[0]}, {audio[1]} Hz)")
    if play:
        log("opening ffplay")
    output = MpegTsWriter(play, audio, args.rewrite_sei)
    try:
        stream_relay(relay, args.resolution, output)
    finally:
        output.close()


if __name__ == "__main__":
    main()
