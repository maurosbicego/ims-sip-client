import socket
import struct
from scapy.all import sniff, IPv6, hexdump, AsyncSniffer, UDP, Raw, SecurityAssociation, ESP, fragment6, send, TCP, raw
import random
import hmac, hashlib


sequence_numbers = {}

def send_request_and_read(destination_ip, destination_port, client_ip: int, client_port: int, request: str) -> str:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,struct.pack('ii', 1, 0))
    sock.bind((client_ip, client_port))
    sock.connect((destination_ip, destination_port))
    print()
    print(request)
    print()
    sock.send(request.encode("UTF-8"))
    response = sock.recv(4096)
    print(response.decode())
    sock.shutdown(socket.SHUT_WR)
    sock.close()
    return response.decode()


def send_esp_req(client_ip, port_c, destination_ip, port_s, request, spi_s, ik):
    ikesp = bytes.fromhex(ik+"00000000")
    inner_ip6 = IPv6(src=client_ip, dst=destination_ip) / UDP(sport=port_c, dport=port_s) / Raw(request)
    print(f"Sending from {client_ip}:{port_c} to {destination_ip}:{port_s}")
    print(request)

    if spi_s in sequence_numbers.keys():
        sequence_numbers[spi_s] += 1
    else:
        sequence_numbers[spi_s] = 1
    print("SEQ NUMS")
    print(sequence_numbers)
    sa_out = SecurityAssociation(
        ESP, spi=spi_s, crypt_algo="NULL",
        auth_algo="HMAC-SHA1-96", auth_key=ikesp, seq_num=sequence_numbers[spi_s]
    )

    esp_pkt = sa_out.encrypt(inner_ip6)

    frags = fragment6(esp_pkt, 1280)
    for f in frags:
        send(f, iface="tun1", verbose=True)

