from scapy.all import sniff, IPv6, hexdump, AsyncSniffer, ESP, UDP, TCP
import requests as r
import hashlib
import hmac
import json
import random
import string
from datetime import datetime
import secrets
from utils import *
import time

import warnings
import argparse
warnings.filterwarnings("ignore")


with open("../session-data.json","r") as fobj:
    vals = json.loads(fobj.read())

parser = argparse.ArgumentParser(prog='IMS SIP Client')
parser.add_argument('-m', '--msisdn', help="Specifiy MSISDN, in international format, without leading 00 or +")
args = parser.parse_args()
if args.msisdn is None:
    print("MSISDN must be specified")
    parser.print_help()
    exit()
mnc = vals["mnc"]
mcc = vals["mcc"]

msisdn = args.msisdn

def handle(pkt):
    if IPv6 in pkt and ESP in pkt:
        esp = pkt[ESP]
        ip6 = pkt[IPv6]
        decoded = decode_esp_packet(pkt, proposed_spi_s, auth.ik)
        if decoded is None:
            decoded = decode_esp_packet(pkt, proposed_spi_c, auth.ik)
        if decoded is None:
            decoded = decode_esp_packet(pkt, spi_c, auth.ik)
        if decoded is None:
            decoded = decode_esp_packet(pkt, spi_s, auth.ik)

        raw = bytes(esp)[8:]
        print(f"\nESP: {ip6.src} → {ip6.dst}  len={len(raw)}")
        if decoded is not None and UDP in decoded:
            received_request = bytes(decoded[UDP].payload).decode("utf-8", "ignore")
            if "Allow: MESSAGE" in received_request and "From: <sip:smsoip.ims" in received_request:
                sms_message = bytes(decoded[UDP].payload).split(b"\r\n\r\n")[1]
                parsed = parse_sms(sms_message)
                print(parsed)
                vals = parse_sip_message(received_request)
                resp = MessageOK(
                    to_uri=vals["to_uri"],
                    from_uri=vals["from_uri"],
                    from_tag=vals["from_tag"],
                    call_id=vals["call_id"],
                    cseq=vals["cseq"],
                    via=vals["via"],
                    to_tag=''.join((random.choice(string.ascii_letters+string.ascii_lowercase+string.ascii_uppercase) for i in range(9)))
                )
                time.sleep(0.1)
                print("SENDING")

                print(client_ip, proposed_port_s, destination_ip, port_c, spi_c, auth.ik)
                send_esp_req(client_ip, proposed_port_s, destination_ip, port_c, resp.build(), spi_c, auth.ik)
                
                ## Sending SMS Reply
                payload = build_rp_ack(parsed["message_reference"])
                reply = SendMessage(
                    msisdn = msisdn,
                    mnc = mnc,
                    mcc = mcc,
                    in_reply_to = vals["call_id"],
                    destination_ip = destination_ip,
                    destination_port = port_s,
                    from_tag = vals["from_tag"],
                    cseq = random.randint(10,500),
                    via = vals["via"],
                    securityline=securityline,
                    payload=payload
                    )
                print("SENDING MESSAGE REPLY")
                send_esp_req(client_ip, proposed_port_c, destination_ip, port_s, reply.build(), spi_s, auth.ik)

        if decoded is not None and TCP in decoded:
            print("RECEIVED TCP DECODED")



t = AsyncSniffer(iface="tun1", prn=handle, store=False, filter="ip6 proto 50")
t.start()



destination_port = 5060
call_id = ''.join((random.choice(string.ascii_letters+string.ascii_lowercase+string.ascii_uppercase) for i in range(24)))
from_tag = ''.join((random.choice(string.ascii_letters+string.ascii_lowercase+string.ascii_uppercase) for i in range(9)))
branch = "z9hG4bK"+(''.join((random.choice(string.ascii_letters+string.ascii_lowercase+string.ascii_uppercase) for i in range(9))))
cnonce = ''.join((random.choice(string.ascii_letters+string.ascii_lowercase+string.ascii_uppercase) for i in range(8)))
client_ip = vals["client-ip"]
destination_ip = vals["p-cscf"]
session_id = ''.join((random.choice(string.ascii_letters+string.ascii_lowercase+string.ascii_uppercase) for i in range(24)))
transport_mode = "trans"
port_c = random.randint(54000,60000)
port_s = random.randint(54000,60000)
spi_c = secrets.randbits(32)
spi_s = secrets.randbits(32)

imsi = r.get("https://localhost/?type=imsi", verify=False).json()["imsi"]
username = f"{imsi}@ims.mnc{mnc}.mcc{mcc}.3gppnetwork.org"
digestURI = f"sip:ims.mnc{mnc}.mcc{mcc}.3gppnetwork.org"
nc = "00000001"
method   = "REGISTER"



register_prompt_auth = RegisterPromptAuth(mnc, mcc, imsi, from_tag, transport_mode, call_id, session_id, client_ip, port_c, port_s, spi_c, spi_s, branch)
register_prompt_auth_response = send_request_and_read(destination_ip, destination_port, client_ip, 5060, register_prompt_auth.build())
securityline = find_security_line(register_prompt_auth_response)
if securityline is None:
    print("No security line found")
    exit()

proposed_spi_c, proposed_spi_s, proposed_port_c, proposed_port_s = spi_c, spi_s, port_c, port_s
spi_c, spi_s, port_c, port_s = parse_security_line(securityline)

auth = WWWAuth()
auth.parse_www_authenticate(register_prompt_auth_response)
passwd = auth.authenticate(username, digestURI, method, nc, cnonce)

time.sleep(2)
verified_register = RegisterWithVerify(mnc, mcc, imsi, from_tag, transport_mode, call_id, session_id, client_ip, proposed_port_c, proposed_port_s, proposed_spi_c, proposed_spi_s, branch, securityline, auth.nonceb64, cnonce, passwd)

send_esp_req(client_ip, proposed_port_c, destination_ip, port_s, verified_register.build(), spi_s, auth.ik)

time.sleep(5)


subscribe = Subscribe(msisdn, mnc, mcc, imsi, from_tag, transport_mode, call_id, session_id, client_ip, proposed_port_c, proposed_port_s, proposed_spi_c, proposed_spi_s, branch, securityline, auth.nonceb64, cnonce, passwd)
#send_esp_req(client_ip, proposed_port_c, destination_ip, port_s, subscribe.build(), spi_s, auth.ik)

time.sleep(2000)
t.stop()
