#!/usr/bin/env python3
"""Port scanner — check open ports on a target host."""
import sys, socket
COMMON = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",27017:"MongoDB"}
def scan(host, ports, timeout=1):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout); result = s.connect_ex((host, port)); s.close()
            if result == 0: open_ports.append(port)
        except: pass
    return open_ports
def cli():
    if len(sys.argv) < 2: print("Usage: port_scan <host> [port1,port2|common|1-1024]"); sys.exit(1)
    host = sys.argv[1]
    if len(sys.argv) > 2:
        arg = sys.argv[2]
        if "-" in arg: lo, hi = map(int, arg.split("-")); ports = range(lo, hi+1)
        elif "," in arg: ports = [int(p) for p in arg.split(",")]
        else: ports = [int(arg)]
    else: ports = COMMON.keys()
    print(f"Scanning {host}...")
    for p in scan(host, ports):
        svc = COMMON.get(p, "?"); print(f"  {p:>5}/tcp  OPEN  {svc}")
if __name__ == "__main__": cli()
