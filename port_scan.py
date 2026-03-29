#!/usr/bin/env python3
"""port_scan - TCP port scanner."""
import sys, argparse, json, socket, concurrent.futures, time

COMMON_PORTS = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",993:"IMAPS",995:"POP3S",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",27017:"MongoDB"}

def scan_port(host, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except:
        return port, False

def main():
    p = argparse.ArgumentParser(description="Port scanner")
    p.add_argument("host")
    p.add_argument("--ports", help="Port range (e.g. 1-1024) or comma-separated")
    p.add_argument("--common", action="store_true", help="Scan common ports only")
    p.add_argument("--timeout", type=float, default=1)
    p.add_argument("--threads", type=int, default=50)
    args = p.parse_args()
    if args.common:
        ports = sorted(COMMON_PORTS.keys())
    elif args.ports:
        if "-" in args.ports:
            start, end = map(int, args.ports.split("-"))
            ports = range(start, end + 1)
        else:
            ports = [int(p) for p in args.ports.split(",")]
    else:
        ports = sorted(COMMON_PORTS.keys())
    t0 = time.time()
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_port, args.host, port, args.timeout): port for port in ports}
        for f in concurrent.futures.as_completed(futures):
            port, is_open = f.result()
            if is_open:
                open_ports.append({"port": port, "service": COMMON_PORTS.get(port, "unknown"), "state": "open"})
    open_ports.sort(key=lambda x: x["port"])
    print(json.dumps({"host": args.host, "scanned": len(ports), "open": len(open_ports), "elapsed_ms": round((time.time()-t0)*1000), "ports": open_ports}, indent=2))

if __name__ == "__main__": main()
