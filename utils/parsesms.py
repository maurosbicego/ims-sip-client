import math


# Source - https://stackoverflow.com/a
# Posted by noiam, modified by community. See post 'Timeline' for change history
# Retrieved 2025-11-23, License - CC BY-SA 3.0

def gsm7bitdecode(f):
   f = ''.join(["{0:08b}".format(int(f[i:i+2], 16)) for i in range(0, len(f), 2)][::-1])
   return ''.join([chr(int(f[::-1][i:i+7][::-1], 2)) for i in range(0, len(f), 7)])



def parse_user_data(data: bytes) -> str:
    tp_params = data[0]
    print(tp_params)

    originating_address_length = int(data[1]) # digits
    print(originating_address_length)

    address_bytes = int(math.ceil(originating_address_length / 2))
    position = 2 + 1 + address_bytes
    originating_address = data[2:position]
    print(originating_address.hex())

    tp_pid = data[position]
    print(tp_pid)
    position += 1

    tp_dcs = data[position]
    print(tp_dcs)
    position += 1

    timestamp = data[position:position+7]
    position += 7

    user_data_length = data[position]
    position += 1

    user_data = data[position:]

    try:
        assert len(user_data) == user_data_length
    except:
        print(f"{len(user_data)} not equal to {user_data_length}")

    print(user_data.hex())

    tp_udhi = bool(tp_params & 0x40)

    if tp_udhi:
        user_data_header_length = user_data[0]
        user_data_header = user_data[1:user_data_header_length+1]
        body = user_data[user_data_header_length+1:]
        print(user_data_header.hex())
        print(body.hex())
    else:
        print("(no UDH)")
        user_data_header = b""
        body = user_data
        print(body.hex())

    try:
        print(gsm7bitdecode(body.hex()))
    except:
        pass

    return ""




def parse_sms(data: bytes) -> dict:
    print(data)
    print(len(data))
    message_type = int(data[0])
    message_reference = int(data[1])
    rp_originator_length = int(data[2])
    rp_orinator_octets = int(math.ceil(rp_originator_length/2)*2)
    position = (3+rp_orinator_octets-1)
    rp_originator = data[3:position]
    print(rp_originator)
    print("Pre destination length Data")
    rp_destination_length = int(data[position])
    # TODO EXTRACT DESTINATION IF LENGTH NOT 0
    position+= (1+rp_destination_length)
    print("Pre User Data")
    print(position)
    user_data_length = int(data[position])
    print(user_data_length)
    position+=1
    user_data = data[position:]
    if len(user_data) != user_data_length:
        print("USER DATA LENGTH MISMATCH")
        print(len(user_data))
        print(user_data_length)
    else:
        print("Parsing finished")

    parse_user_data(user_data)
    return {
        "message_type": message_type,
        "rp_originator": rp_originator,
        "message_reference": message_reference,
        "user_data_length": user_data_length,
        "user_data": user_data
    }