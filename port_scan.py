#!/usr/bin/env python3
"""port_scan — Quick TCP port scanner with banner grabbing."""
import sys, socket, argparse, concurrent.futures

COMMON_PORTS = {22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',
    143:'IMAP',443:'HTTPS',445:'SMB',993:'IMAPS',995:'POP3S',
    3306:'MySQL',5432:'PostgreSQL',6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',
    27017:'MongoDB',3000:'Dev',5000:'Dev',8000:'Dev'}

def scan_port(host, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = ''
        try:
            s.send(b'\r\n')
            banner = s.recv(256).decode(errors='replace').strip()[:60]
        except: pass
        s.close()
        return port, True, banner
    except: return port, False, ''

def cmd_scan(args):
    host = args.host
    if args.ports:
        ports = []
        for p in args.ports.split(','):
            if '-' in p:
                a,b = p.split('-'); ports.extend(range(int(a),int(b)+1))
            else: ports.append(int(p))
    else:
        ports = sorted(COMMON_PORTS.keys())
    
    print(f'Scanning {host} ({len(ports)} ports)...\n')
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_port, host, p, args.timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            port, is_open, banner = f.result()
            if is_open:
                svc = COMMON_PORTS.get(port, '')
                b = f'  {banner}' if banner else ''
                print(f'  {port:>5}/tcp  open  {svc:<15}{b}')
                open_ports.append(port)
    
    print(f'\n{len(open_ports)} open / {len(ports)} scanned')

def main():
    p = argparse.ArgumentParser(description='TCP port scanner')
    p.add_argument('host')
    p.add_argument('--ports','-p', help='Ports: 80,443 or 1-1024')
    p.add_argument('--timeout','-t', type=float, default=1.0)
    p.add_argument('--threads', type=int, default=50)
    p.set_defaults(func=cmd_scan)
    a = p.parse_args(); a.func(a)

if __name__=='__main__': main()
