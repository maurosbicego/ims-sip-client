from datetime import datetime
import random
import string

class SendMessage:
    def __init__(self, 
                 msisdn,
                 mnc,
                 mcc,
                 in_reply_to,
                 destination_ip,
                 destination_port,
                 from_tag,
                 cseq,
                 via,
                 securityline,
                 payload):
        self.msisdn = msisdn
        self.mnc = mnc
        self.mcc = mcc
        self.in_reply_to = in_reply_to
        self.from_tag = from_tag
        self.call_id = ''.join((random.choice(string.ascii_letters+string.ascii_lowercase+string.ascii_uppercase) for i in range(24)))
        self.tag = ''.join((random.choice(string.ascii_letters+string.ascii_lowercase+string.ascii_uppercase) for i in range(9)))
        self.cseq = cseq
        self.via = via
        self.securityline = securityline
        self.payload = payload
        self.destination_ip = destination_ip
        self.destination_port = destination_port

    def build(self):
        timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')+"+02:00"
        headers = f"""\
MESSAGE sip:smsoip.ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org SIP/2.0\r\n\
Call-ID: {self.call_id}\r\n\
From: <sip:+{self.msisdn}@ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org>;tag={self.tag}\r\n\
To: <sip:smsoip.ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org>\r\n\
In-Reply-To: {self.in_reply_to}\r\n\
Request-Disposition: no-fork\r\n\
Accept-Contact: *;+g.3gpp.smsip\r\n\
CSeq: {self.cseq} MESSAGE\r\n\
Via: {self.via}\r\n\
Allow: ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REFER,\r\n\
P-Preferred-Identity: sip:+{self.msisdn}@ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org\r\n\
Max-Forwards: 70\r\n\
Supported: 100rel,path,replaces\r\n\
User-Agent: iOS/15.7 iPhone\r\n\
Route: <sip:[{self.destination_ip}]:{self.destination_port};lr>, <sip:[{self.destination_ip}]:{self.destination_port};lr;transport=tcp>\r\n\
P-Access-Network-Info: 3GPP-E-UTRAN-FDD;local-time-zone="{timestamp}";utran-cell-id-3gpp=24007deadbeef123\r\n\
Security-Verify: {self.securityline}\r\n\
Require: sec-agree\r\n\
Proxy-Require: sec-agree\r\n\
Content-Type: application/vnd.3gpp.sms\r\n\
Content-Length: 6\r\n\r\n\
"""
        return headers.encode("UTF-8")+self.payload+b"\r\n\r\n"