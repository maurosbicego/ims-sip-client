
from datetime import datetime

class RegisterWithVerify:
    def __init__(self, mnc, mcc, imsi, from_tag, transport_mode, call_id, session_id, client_ip, port_c, port_s, spi_c, spi_s, branch, securityline, nonce, cnonce, password, cseq=2):
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
REGISTER sip:ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org SIP/2.0\r\n\
To: <sip:{self.imsi}@ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org>\r\n\
From: <sip:{self.imsi}@ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org>;tag={self.from_tag}\r\n\
Expires: 600000\r\n\
Require: sec-agree\r\n\
Proxy-Require: sec-agree\r\n\
Security-Client: ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod={self.transport_mode};port-c={self.port_c};port-s={self.port_s};prot=esp;spi-c={self.spi_c};spi-s={self.spi_s}\r\n\
Call-ID: {self.call_id}\r\n\
Session-ID: {self.session_id}\r\n\
Contact: <sip:[{self.client_ip}]:{self.port_s}>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.mid-call;+g.3gpp.ps2cs-srvcc-orig-pre-alerting;+g.3gpp.smsip;+g.3gpp.srvcc-alerting;+sip.instance="<urn:gsma:imei:12345678-123456-0>"\r\n\
Authorization: Digest qop=auth,nc=00000001,nonce="{self.nonce}",uri="sip:ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org",algorithm=AKAv1-MD5,response="{self.password}",username="{self.imsi}@ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org",realm="epc.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org",cnonce="{self.cnonce}"\r\n\
CSeq: {self.cseq} REGISTER\r\n\
Via: SIP/2.0/TCP [{self.client_ip}]:5060;branch={self.branch};rport\r\n\
Allow: ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REFER,UPDATE\r\n\
Security-Verify: {self.securityline}\r\n\
Content-Length: 0\r\n\r\n\
"""

        return data