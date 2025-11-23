from scapy.all import *
from scapy.layers.ipsec import SecurityAssociation, ESP

def decode_esp_packet(pkt, spi_in, ik):
    """
    Decrypt inbound ESP transport-mode packets.
    Requires: SPI, key (HMAC-SHA1-96), and legally obtained traffic.
    Returns the inner IPv6 or IPv4 or Raw payload.
    """

    # Convert ik to binary, your code adds 4 bytes zero-padding:
    auth_key = bytes.fromhex(ik + "00000000")

    # Build Security Association for *incoming* direction
    try:
        sa_in = SecurityAssociation(
            ESP,
            spi=spi_in,
            crypt_algo="NULL",       # no encryption
            auth_algo="HMAC-SHA1-96",
            auth_key=auth_key
        )

        # Only decrypt if this packet actually contains ESP
        if ESP not in pkt:
            return None

        # Perform ESP decryption
        inner = sa_in.decrypt(pkt)

        return inner
    except:
        return None