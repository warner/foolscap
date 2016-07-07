"""
tcp4       0      0  10.0.1.43.3689         10.0.1.65.51322        ESTABLISHED
tcp4       0      0  10.0.1.43.3689         10.0.1.65.51321        ESTABLISHED
tcp6       0      0  fe80::aa20:66ff:.3689  fe80::1480:41b5:.51303 CLOSE_WAIT
tcp4       0      0  10.0.1.43.53220        38.121.104.91.443      ESTABLISHED
tcp4       0      0  127.0.0.1.8066         *.*                    LISTEN
tcp4       0      0  10.0.1.43.52705        204.246.122.77.993     ESTABLISHED
"""

# on OS-X, run as "netstat -p tcp -na |parse-netstat.py"

import os,sys,re

def parse_line(line):
    if "CLOSED" in line:
        return (None,None)
    pieces = line.split()
    state = pieces[-1]
    local_addr = pieces[3]
    dot = local_addr.rfind(".")
    local_interface = local_addr[:dot]
    local_port = local_addr[dot+1:]
    if local_port == "*":
        return 0
    return int(local_port)

lines = [line.strip() for line in sys.stdin.readlines()
         if line.startswith("tcp")]
lines.sort(key=parse_line)
for line in lines:
    if "CLOSED" in line:
        continue
    print line

