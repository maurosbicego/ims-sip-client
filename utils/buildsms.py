def build_rp_ack(message_reference: int) -> bytes:
    return b"\02"+bytes([message_reference])+b"\00\00"