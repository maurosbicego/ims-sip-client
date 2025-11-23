
from datetime import datetime

class Subscribe:
    def __init__(self, msisdn, mnc, mcc, imsi, from_tag, transport_mode, call_id, session_id, client_ip, port_c, port_s, spi_c, spi_s, branch, securityline, nonce, cnonce, password, cseq=2):
        self.msisdn = msisdn
        self.mnc = mnc
        self.mcc = mcc
        self.imsi = imsi
        self.from_tag = from_tag
        self.transport_mode = transport_mode
        self.call_id = call_id
        self.session_id = session_id
        self.client_ip = client_ip
        self.port_c = port_c
        self.port_s = port_s
        self.spi_c = spi_c
        self.spi_s = spi_s
        self.cseq = cseq
        self.branch = branch
        self.nonce = nonce
        self.cnonce = cnonce
        self.password = password
        self.securityline = securityline
    
    def build(self):
        timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')+"+02:00"

        data = f"""\
SUBSCRIBE sip:+{self.msisdn}@ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org SIP/2.0\r\n\
Expires: 600000\r\n\
Event: reg\r\n\
Accept: application/reginfo+xml\r\n\
From: <sip:+{self.msisdn}@ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org>;tag={self.from_tag}\r\n\
To: <sip:+{self.msisdn}@ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org>\r\n\
Call-ID: {self.call_id}\r\n\
Session-ID: {self.session_id}\r\n\
Contact: sip:[{self.client_ip}]:{self.port_s}\r\n\
CSeq: 1 SUBSCRIBE\r\n\
Via: SIP/2.0/UDP [{self.client_ip}]:{self.port_c};branch={self.branch};rport\r\n\
Allow: ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REFER,UPDATE\r\n\
P-Preferred-Identity: sip:+{self.msisdn}@ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org\r\n\
Max-Forwards: 70\r\n\
Supported: 100rel,path,replaces\r\n\
User-Agent: iOS/15.7 iPhone\r\n\
Security-Verify: {self.securityline}\r\n\
Require: sec-agree\r\n\
Proxy-Require: sec-agree\r\n\
Route: <sip:[2001:4d98:3ffc:affe::1]:5061;lr>, <sip:[2001:4d98:3ffc:affe::1]:5061;lr;transport=tcp>\r\n\
Content-Length: 0\r\n\r\n\
"""

        return data