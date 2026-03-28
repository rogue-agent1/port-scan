#!/usr/bin/env python3
"""TCP port scanner with service detection."""
import sys, socket, concurrent.futures, time

SERVICES = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',
            143:'IMAP',443:'HTTPS',445:'SMB',993:'IMAPS',995:'POP3S',3306:'MySQL',
            5432:'PostgreSQL',6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',
            27017:'MongoDB',3000:'Dev',5000:'Dev',9200:'Elasticsearch'}

def scan_port(host, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except:
        return port, False

def scan(host, ports=None, timeout=1, workers=50):
    if ports is None: ports = list(SERVICES.keys()) + list(range(8000,8100))
    ports = sorted(set(ports))
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            port, is_open = f.result()
            if is_open:
                service = SERVICES.get(port, 'unknown')
                open_ports.append((port, service))
    return sorted(open_ports)

if __name__ == '__main__':
    if len(sys.argv) < 2: print("Usage: port_scan.py <host> [port-range] [-t timeout]"); sys.exit(1)
    host = sys.argv[1]
    timeout = float(sys.argv[sys.argv.index('-t')+1]) if '-t' in sys.argv else 1
    ports = None
    if len(sys.argv) > 2 and '-' in sys.argv[2]:
        start, end = map(int, sys.argv[2].split('-'))
        ports = list(range(start, end+1))
    print(f"Scanning {host}...\n")
    t = time.time()
    results = scan(host, ports, timeout)
    elapsed = time.time() - t
    if results:
        print(f"{'PORT':>7} {'STATE':>7}  SERVICE")
        for port, svc in results:
            print(f"{port:>7} {'open':>7}  {svc}")
    else:
        print("No open ports found.")
    print(f"\nScanned in {elapsed:.1f}s")
