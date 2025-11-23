import re

def parse_sip_message(raw):
    """
    Parse a SIP MESSAGE request and return the fields needed for building a 200 OK.
    Returns a dict with:
        via, from_uri, from_tag, to_uri, call_id, cseq
    """

    lines = raw.splitlines()
    headers = {}

    last_header = None
    for line in lines[1:]:
        if line.strip() == "":
            break
        if ":" in line:
            name, value = line.split(":", 1)
            name = name.strip()
            value = value.strip()
            headers[name] = value
            last_header = name
        else:
            if last_header:
                headers[last_header] += " " + line.strip()

    port_match = re.search(r']:(.*) SIP', lines[0])
    port = port_match.group(1) if port_match else None

    via = headers.get("Via")


    from_header = headers.get("From") or headers.get("f")
    from_uri_match = re.search(r'<(sip:[^>]+)>', from_header)
    
    from_tag_match = re.search(r'tag=([^;>\s]+)', from_header)
    from_uri = from_uri_match.group(1) if from_uri_match else None
    from_tag = from_tag_match.group(1) if from_tag_match else None


    to_header = headers.get("To") or headers.get("t")
    to_uri_match = re.search(r'<(sip:[^>]+)>', to_header)
    to_uri = to_uri_match.group(1) if to_uri_match else None
    

    call_id = headers.get("Call-ID") or headers.get("i")


    cseq_header = headers.get("CSeq")
    cseq_number = int(cseq_header.split()[0]) if cseq_header else None

    return {
        "via": via,
        "from_uri": from_uri,
        "from_tag": from_tag,
        "to_uri": to_uri,
        "call_id": call_id,
        "cseq": cseq_number,
        "port": port
    }
