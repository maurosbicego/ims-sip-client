from datetime import datetime

class MessageOK:
    def __init__(self, 
                 to_uri,
                 from_uri,
                 from_tag,
                 call_id,
                 cseq,
                 via,
                 to_tag,
                 status="200 OK"):
        self.to_uri = to_uri
        self.from_uri = from_uri
        self.from_tag = from_tag
        self.call_id = call_id
        self.cseq = cseq
        self.via = via
        self.to_tag = to_tag
        self.status = status

    def build(self):
        timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')+"+02:00"
        return f"""\
SIP/2.0 {self.status}\r\n\
Via: {self.via}\r\n\
From: <{self.from_uri}>;tag={self.from_tag}\r\n\
To: <{self.to_uri}>;tag={self.to_tag}\r\n\
Call-ID: {self.call_id}\r\n\
CSeq: {self.cseq} MESSAGE\r\n\
Allow: ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REFER,UPDATE\r\n\
Supported: 100rel,path,replaces\r\n\
User-Agent: iOS/15.7 iPhone\r\n\
P-Access-Network-Info: IEEE-802.11;country=CH;i-wlan-node-id=ffffffffffff;local-time-zone="{timestamp}"\r\n\
Content-Length: 0\r\n\r\n\
"""