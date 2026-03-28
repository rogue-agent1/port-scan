#!/usr/bin/env python3
"""port_scan - TCP port scanner with banner grabbing."""
import sys,socket,concurrent.futures
def scan_port(host,port,timeout=1):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(timeout)
        s.connect((host,port));banner=""
        try:s.send(b"\r\n");banner=s.recv(1024).decode(errors="ignore").strip()
        except:pass
        s.close();return port,True,banner
    except:return port,False,""
def scan(host,ports,threads=50):
    results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures={ex.submit(scan_port,host,p):p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            p,open_,banner=f.result()
            if open_:results.append((p,banner))
    return sorted(results)
COMMON=[21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443,27017]
if __name__=="__main__":
    if len(sys.argv)<2:print("Usage: port_scan.py <host> [port-range|common]");sys.exit(1)
    host=sys.argv[1]
    if len(sys.argv)>2 and "-" in sys.argv[2]:
        a,b=sys.argv[2].split("-");ports=range(int(a),int(b)+1)
    elif len(sys.argv)>2:ports=[int(p) for p in sys.argv[2].split(",")]
    else:ports=COMMON
    print(f"Scanning {host}...");results=scan(host,ports)
    for p,b in results:print(f"  {p:>5}/tcp open  {b[:60]}" if b else f"  {p:>5}/tcp open")
    print(f"\n{len(results)} open ports found")
