from getpass import getpass
import plistlib as plist
import json
import uuid
import pbkdf2
import requests
import hashlib
import hmac
import base64
import locale
from datetime import datetime
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Hash import SHA256
import os
import logging
import sys
try:
    import http.client as http_client
except Exception:
    http_client = None

# Created here so that it is consistent
USER_ID = uuid.uuid4()
DEVICE_ID = uuid.uuid4()

# Configure SRP library for compatibility with Apple's implementation
srp.rfc5054_enable()
srp.no_username_in_x()

# Disable SSL Warning
import urllib3
urllib3.disable_warnings()

# Debug flag
DEBUG_HTTP = os.environ.get('DEBUG_HTTP', '').lower() in ('1', 'true', 'yes')

# Configure verbose HTTP logging if requested
if DEBUG_HTTP:
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='[%(levelname)s] %(message)s')
    logging.getLogger('urllib3').setLevel(logging.DEBUG)
    if http_client is not None:
        http_client.HTTPConnection.debuglevel = 1

ANISETTE_URL = os.environ.get('ANISETTE_URL', 'http://anisette:6969')  # overridable in container

# --- Debug helpers ---
REDACTED = '***REDACTED***'

_SENSITIVE_HEADER_KEYS = {
    'authorization', 'cookie', 'set-cookie', 'x-apple-identity-token', 'x-apple-i-md', 'x-apple-i-md-m',
    'x-apple-i-md-lu', 'x-mme-device-id', 'x-apple-i-srl-no', 'security-code'
}

_SENSITIVE_BODY_KEYS = {
    'password', 'securitycode', 'code', 'pet', 'token', 'searchPartyToken', 'searchpartyToken'
}

def _lower_keys(d):
    return {str(k).lower(): v for k, v in d.items()}

def _redact_headers(headers: dict) -> dict:
    try:
        out = {}
        for k, v in headers.items():
            if str(k).lower() in _SENSITIVE_HEADER_KEYS:
                out[k] = REDACTED
            else:
                out[k] = v
        return out
    except Exception:
        return headers

def _redact_body(data):
    try:
        if data is None:
            return None
        if isinstance(data, (bytes, bytearray)):
            # Try to parse as plist for better visibility; otherwise show size only
            try:
                parsed = plist.loads(data)
                return _redact_body(parsed)
            except Exception:
                return f'<{type(data).__name__} {len(data)} bytes>'
        if isinstance(data, str):
            # Avoid dumping huge strings; truncate
            return data[:1024] + ('…' if len(data) > 1024 else '')
        if isinstance(data, dict):
            red = {}
            for k, v in data.items():
                lk = str(k).lower()
                if lk in _SENSITIVE_BODY_KEYS:
                    red[k] = REDACTED
                else:
                    red[k] = _redact_body(v)
            return red
        if isinstance(data, list):
            return [_redact_body(x) for x in data]
        return data
    except Exception:
        return data

def _truncate_bytes(b: bytes, n: int = 1024) -> str:
    try:
        s = b.decode(errors='replace')
        return s[:n] + ('…' if len(s) > n else '')
    except Exception:
        return f'<bytes {len(b)}>'

def _debug(msg, *args):
    if DEBUG_HTTP:
        try:
            print(msg % args if args else msg)
        except Exception:
            print(msg)

def icloud_login_mobileme(username='', password='', second_factor='sms'):
    if not username:
        username = input('Apple ID: ')
    if not password:
        password = getpass('Password: ')

    g = gsa_authenticate(username, password, second_factor)
    pet = g["t"]["com.apple.gs.idms.pet"]["token"]
    adsid = g["adsid"]

    data = {
        "apple-id": username,
        "delegates": {"com.apple.mobileme":{}},
        "password": pet,
        "client-id": str(USER_ID),
    }
    data = plist.dumps(data)

    headers = {
        "X-Apple-ADSID": adsid,
        "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
        "X-Mme-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>'
    }
    headers.update(generate_anisette_headers())

    if DEBUG_HTTP:
        _debug('HTTP POST https://setup.icloud.com/setup/iosbuddy/loginDelegates')
        _debug('  headers: %s', json.dumps(_redact_headers(headers), ensure_ascii=False))
        try:
            _debug('  body (plist, redacted): %s', json.dumps(_redact_body({
                "apple-id": username,
                "delegates": {"com.apple.mobileme": {}},
                "password": REDACTED,
                "client-id": str(USER_ID),
            }), ensure_ascii=False))
        except Exception:
            pass

    r = requests.post(
        "https://setup.icloud.com/setup/iosbuddy/loginDelegates",
        auth=(username, pet),
        data=data,
        headers=headers,
        verify=False,
    )

    if DEBUG_HTTP:
        _debug('  -> %s %s', r.status_code, r.reason)
        _debug('  resp headers: %s', json.dumps(dict(r.headers), ensure_ascii=False))
        _debug('  resp body: %s', _truncate_bytes(r.content))

    return plist.loads(r.content)

def gsa_authenticate(username, password, second_factor='sms'):
    # Password is None as we'll provide it later
    usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = usr.start_authentication()

    r = gsa_authenticated_request({"A2k": A, "ps": ["s2k", "s2k_fo"], "u": username, "o": "init"})

    if r["sp"] != "s2k":
        print(f"This implementation only supports s2k. Server returned {r['sp']}")
        return

    # Change the password out from under the SRP library, as we couldn't calculate it without the salt.
    usr.p = encrypt_password(password, r["s"], r["i"])

    M = usr.process_challenge(r["s"], r["B"])

    # Make sure we processed the challenge correctly
    if M is None:
        print("Failed to process challenge")
        return

    r = gsa_authenticated_request({"c": r["c"], "M1": M, "u": username, "o": "complete"})

    # Make sure that the server's session key matches our session key (and thus that they are not an imposter)
    if "M2" not in r:
        print("GSA 'complete' response missing M2. Full response for debugging:")
        try:
            print(json.dumps(r, indent=2, ensure_ascii=False))
        except Exception:
            print(r)
        raise KeyError("M2")
    usr.verify_session(r["M2"])
    if not usr.authenticated():
        print("Failed to verify session")
        return

    spd = decrypt_cbc(usr, r["spd"])
    # For some reason plistlib doesn't accept it without the header...
    PLISTHEADER = b"""\
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
"""
    spd = plist.loads(PLISTHEADER + spd)

    if "au" in r["Status"] and r["Status"]["au"] in ["trustedDeviceSecondaryAuth","secondaryAuth"]:
        print("2FA required, requesting code")
        if DEBUG_HTTP:
            _debug('2FA path: %s (selected: %s)', r["Status"]["au"], second_factor)
        # Replace bytes with strings
        for k, v in spd.items():
            if isinstance(v, bytes):
                spd[k] = base64.b64encode(v).decode()
        if second_factor == 'sms':
            sms_second_factor(spd["adsid"], spd["GsIdmsToken"])
        elif second_factor == 'trusted_device':
            trusted_second_factor(spd["adsid"], spd["GsIdmsToken"])
        return gsa_authenticate(username, password)
    elif "au" in r["Status"]:
        print(f"Unknown auth value {r['Status']['au']}")
        if DEBUG_HTTP:
            try:
                _debug('Full Status: %s', json.dumps(r.get('Status', {}), ensure_ascii=False))
            except Exception:
                pass
        return
    else:
        return spd

def gsa_authenticated_request(parameters):
    body = {
        "Header": {"Version": "1.0.1"},
        "Request": {"cpd": generate_cpd()},
    }
    body["Request"].update(parameters)

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        "X-MMe-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>'
    }

    try:
        if DEBUG_HTTP:
            _debug('HTTP POST https://gsa.apple.com/grandslam/GsService2 (operation: %s)', parameters.get('o'))
            _debug('  headers: %s', json.dumps({
                "Content-Type": "text/x-xml-plist",
                "Accept": "*/*",
                "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
                "X-MMe-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>'
            }, ensure_ascii=False))
            _debug('  body (plist, redacted): %s', json.dumps(_redact_body(body), ensure_ascii=False))
        resp = requests.post(
            "https://gsa.apple.com/grandslam/GsService2",
            headers=headers,
            data=plist.dumps(body),
            verify=False,
            timeout=10,
        )
        if DEBUG_HTTP:
            _debug('  -> %s %s', resp.status_code, resp.reason)
            _debug('  resp headers: %s', json.dumps(dict(resp.headers), ensure_ascii=False))
            _debug('  resp body: %s', _truncate_bytes(resp.content))
        resp.raise_for_status()
        parsed = plist.loads(resp.content)
        if not isinstance(parsed, dict) or "Response" not in parsed:
            print("Unexpected GSA response structure. Raw content (truncated):")
            print(resp.content[:512])
        return parsed["Response"]
    except requests.exceptions.RequestException as e:
        print(f"Request to GSA failed: {e}")
        if 'resp' in locals():
            print(f"Status: {resp.status_code}")
            print("Body (truncated):")
            print(resp.content[:512])
        raise

def generate_cpd():
    cpd = {
        # Many of these values are not strictly necessary, but may be tracked by Apple
        "bootstrap": True,  # All implementations set this to true
        "icscrec": True,  # Only AltServer sets this to true
        "pbe": False,  # All implementations explicitly set this to false
        "prkgen": True,  # I've also seen ckgen
        "svct": "iCloud",  # In certian circumstances, this can be 'iTunes' or 'iCloud'
    }

    cpd.update(generate_anisette_headers())
    return cpd

def generate_anisette_headers():
    try:
        import pyprovision
        from ctypes import c_ulonglong
        import secrets
        adi = pyprovision.ADI("./anisette/")
        adi.provisioning_path = "./anisette/"
        device = pyprovision.Device("./anisette/device.json")
        if not device.initialized:
            # Pretend to be a MacBook Pro
            device.server_friendly_description = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"
            device.unique_device_identifier = str(uuid.uuid4()).upper()
            device.adi_identifier = secrets.token_hex(8).lower()
            device.local_user_uuid = secrets.token_hex(32).upper()
        adi.identifier = device.adi_identifier
        dsid = c_ulonglong(-2).value
        is_prov = adi.is_machine_provisioned(dsid)
        if not is_prov:
            print("provisioning...")
            provisioning_session = pyprovision.ProvisioningSession(adi, device)
            provisioning_session.provision(dsid)
        otp = adi.request_otp(dsid)
        a = {"X-Apple-I-MD": base64.b64encode(bytes(otp.one_time_password)).decode(), "X-Apple-I-MD-M": base64.b64encode(bytes(otp.machine_identifier)).decode()}
    except ImportError:
        print(f'pyprovision is not installed, querying {ANISETTE_URL} for an anisette server')
        try:
            r = requests.get(ANISETTE_URL, timeout=5)
            if DEBUG_HTTP:
                _debug('HTTP GET %s -> %s %s', ANISETTE_URL, r.status_code, r.reason)
                try:
                    _debug('  resp keys: %s', list(json.loads(r.text).keys()))
                except Exception:
                    _debug('  resp body: %s', _truncate_bytes(r.content))
            r.raise_for_status()
            h = json.loads(r.text)
        except Exception as e:
            if DEBUG_HTTP:
                _debug('Anisette GET failed: %s', e)
            raise
        a = {"X-Apple-I-MD": h["X-Apple-I-MD"], "X-Apple-I-MD-M": h["X-Apple-I-MD-M"]}
    a.update(generate_meta_headers(user_id=USER_ID, device_id=DEVICE_ID))
    return a

def generate_meta_headers(serial="0", user_id=uuid.uuid4(), device_id=uuid.uuid4()):
    return {
        "X-Apple-I-Client-Time": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "X-Apple-I-TimeZone": str(datetime.utcnow().astimezone().tzinfo),
        "loc": locale.getdefaultlocale()[0] or "en_US",
        "X-Apple-Locale": locale.getdefaultlocale()[0] or "en_US",
        "X-Apple-I-MD-RINFO": "17106176",  # either 17106176 or 50660608
        "X-Apple-I-MD-LU": base64.b64encode(str(user_id).upper().encode()).decode(),
        "X-Mme-Device-Id": str(device_id).upper(),
        "X-Apple-I-SRL-NO": serial,  # Serial number
    }

def encrypt_password(password, salt, iterations):
    p = hashlib.sha256(password.encode("utf-8")).digest()
    return pbkdf2.PBKDF2(p, salt, iterations, SHA256).read(32)

def create_session_key(usr, name):
    k = usr.get_session_key()
    if k is None:
        raise Exception("No session key")
    return hmac.new(k, name.encode(), hashlib.sha256).digest()

def decrypt_cbc(usr, data):
    extra_data_key = create_session_key(usr, "extra data key:")
    extra_data_iv = create_session_key(usr, "extra data iv:")
    # Get only the first 16 bytes of the iv
    extra_data_iv = extra_data_iv[:16]

    # Decrypt with AES CBC
    cipher = Cipher(algorithms.AES(extra_data_key), modes.CBC(extra_data_iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    # Remove PKCS#7 padding
    padder = padding.PKCS7(128).unpadder()
    return padder.update(data) + padder.finalize()

def trusted_second_factor(dsid, idms_token):
    identity_token = base64.b64encode((dsid + ":" + idms_token).encode()).decode()

    headers = {
        "Content-Type": "text/x-xml-plist",
        "User-Agent": "Xcode",
        "Accept": "text/x-xml-plist",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Mme-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>'
    }

    headers.update(generate_anisette_headers())

    # This will trigger the 2FA prompt on trusted devices
    # We don't care about the response, it's just some HTML with a form for entering the code
    # Easier to just use a text prompt
    if DEBUG_HTTP:
        _debug('HTTP GET https://gsa.apple.com/auth/verify/trusteddevice')
        _debug('  headers: %s', json.dumps(_redact_headers(headers), ensure_ascii=False))
    resp_trigger = requests.get(
        "https://gsa.apple.com/auth/verify/trusteddevice",
        headers=headers,
        verify=False,
        timeout=10,
    )
    if DEBUG_HTTP:
        _debug('  -> %s %s', resp_trigger.status_code, resp_trigger.reason)
        _debug('  resp headers: %s', json.dumps(dict(resp_trigger.headers), ensure_ascii=False))
        _debug('  resp body: %s', _truncate_bytes(resp_trigger.content))

    # Prompt for the 2FA code. It's just a string like '123456', no dashes or spaces
    code = getpass("Enter 2FA code: ")
    headers["security-code"] = code

    # Send the 2FA code to Apple
    if DEBUG_HTTP:
        _debug('HTTP GET https://gsa.apple.com/grandslam/GsService2/validate')
        _debug('  headers: %s', json.dumps(_redact_headers(headers), ensure_ascii=False))
    resp = requests.get(
        "https://gsa.apple.com/grandslam/GsService2/validate",
        headers=headers,
        verify=False,
        timeout=10,
    )
    if DEBUG_HTTP:
        _debug('  -> %s %s', resp.status_code, resp.reason)
        _debug('  resp headers: %s', json.dumps(dict(resp.headers), ensure_ascii=False))
        _debug('  resp body: %s', _truncate_bytes(resp.content))
    if resp.ok:
        print("2FA successful")


def sms_second_factor(dsid, idms_token):
    identity_token = base64.b64encode((dsid + ":" + idms_token).encode()).decode()

    # TODO: Actually do this request to get user prompt data
    # a = requests.get("https://gsa.apple.com/auth", verify=False)
    # This request isn't strictly necessary though, 
    # and most accounts should have their id 1 SMS, if not contribute ;)

    headers = {
        "User-Agent": "Xcode",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Mme-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>'
    }

    headers.update(generate_anisette_headers())

    # TODO: Actually get the correct id, probably in the above GET
    body = {"phoneNumber":{"id":1},"mode":"sms"}

    # This will send the 2FA code to the user's phone over SMS
    # We don't care about the response, it's just some HTML with a form for entering the code
    # Easier to just use a text prompt
    if DEBUG_HTTP:
        _debug('HTTP POST https://gsa.apple.com/auth/verify/phone/')
        _debug('  headers: %s', json.dumps(_redact_headers(headers), ensure_ascii=False))
        _debug('  body: %s', json.dumps(_redact_body(body), ensure_ascii=False))
    t = requests.post(
        "https://gsa.apple.com/auth/verify/phone/",
        json=body,
        headers=headers,
        verify=False,
        timeout=5
    )
    if t.status_code == 404:
        # Some deployments require no trailing slash
        if DEBUG_HTTP:
            _debug('Retrying without trailing slash...')
        t = requests.post(
            "https://gsa.apple.com/auth/verify/phone",
            json=body,
            headers=headers,
            verify=False,
            timeout=5
        )
    if DEBUG_HTTP:
        _debug('  -> %s %s', t.status_code, t.reason)
        _debug('  resp headers: %s', json.dumps(dict(t.headers), ensure_ascii=False))
        _debug('  resp body: %s', _truncate_bytes(t.content))
    # Prompt for the 2FA code. It's just a string like '123456', no dashes or spaces
    code = input("Enter 2FA code: ")

    body['securityCode'] = {'code': code}

    # Send the 2FA code to Apple
    if DEBUG_HTTP:
        _debug('HTTP POST https://gsa.apple.com/auth/verify/phone/securitycode')
        _debug('  headers: %s', json.dumps(_redact_headers(headers), ensure_ascii=False))
        _debug('  body: %s', json.dumps(_redact_body(body), ensure_ascii=False))
    resp = requests.post(
        "https://gsa.apple.com/auth/verify/phone/securitycode",
        json=body,
        headers=headers,
        verify=False,
        timeout=5,
    )
    if DEBUG_HTTP:
        _debug('  -> %s %s', resp.status_code, resp.reason)
        _debug('  resp headers: %s', json.dumps(dict(resp.headers), ensure_ascii=False))
        _debug('  resp body: %s', _truncate_bytes(resp.content))
    if resp.ok:
        print("2FA successful")
