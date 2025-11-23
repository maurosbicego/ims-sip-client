import re

def find_security_line(response: str) -> str | None:
    for line in response.splitlines():
        if "Security-Server:" in line:
            return line.split(" ")[1]
    return None


def parse_security_line(securityline: str) -> (int, int, int, int):
    security_params = re.findall('ealg=null;spi-c=(.*);spi-s=(.*);port-c=(.*);port-s=(.*)', securityline)
    if len(security_params) == 0:
        print("No security parameters found")
        return (0,0,0,0)
    return tuple(map(int, security_params[0]))