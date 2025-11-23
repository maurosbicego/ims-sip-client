import re
import base64
import requests as r
import hashlib, binascii

def md5hex_bytes(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()

def md5hex_str(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

def aka_digest_response_raw_res(
    username: str,
    realm: str,
    uri: str,
    method: str,
    nonce_b64_text: str,
    nc: str,
    cnonce: str,
    qop: str,
    res_hex: str,
) -> str:
    """
    AKAv1-MD5 per RFC 3310 + NIST stack style, with RES fed as RAW BYTES in A1.

    HA1 = MD5( (username ":" realm ":" RES_raw_bytes) )
    HA2 = MD5( method ":" uri )
    response = MD5( HA1_hex ":" nonce_b64_text ":" nc ":" cnonce ":" qop ":" HA2_hex )
    """
    res_bytes = binascii.unhexlify(res_hex)

    a1_bytes = (f"{username}:{realm}:".encode() + res_bytes)
    HA1 = md5hex_bytes(a1_bytes)                  # hex string
    HA2 = md5hex_str(f"{method}:{uri}")           # hex string

    kd = f"{HA1}:{nonce_b64_text}:{nc}:{cnonce}:{qop}:{HA2}"
    return md5hex_str(kd)

    
class WWWAuth:
    def __init__(self):
        self.realm = ""
        self.nonceb64 = ""
        self.qop = "auth"

    def parse_www_authenticate(self, request: str) -> bool:
        noncesearch = re.findall('nonce="(.*)",algorithm=AKA', request)
        if len(noncesearch) == 0:
            print("No Nonce found")
            return False
        self.nonceb64 = noncesearch[0]
        realmsearch = re.findall('realm="(.*)",nonce=', request)

        if len(realmsearch) == 0:
            print("No realm found")
            return False
        self.realm = realmsearch[0]
        return True
        

    def authenticate(self, username, digestURI, method, nc, cnonce):
        hexnonce = base64.b64decode(self.nonceb64).hex()
        rand = hexnonce[:32]
        autn = hexnonce[32:]
        res = r.get("https://localhost/?type=rand-autn&rand={}&autn={}".format(rand,autn), verify=False).json()
        password = res["res"]
        self.ik = res["ik"]
        self.ck = res["ck"]
        if password is None:
            print("Error when running www auth from SIM")
            exit()

        wwwauth = aka_digest_response_raw_res(
            username, self.realm, digestURI, method, self.nonceb64, nc, cnonce, self.qop, password
        )
        return wwwauth
