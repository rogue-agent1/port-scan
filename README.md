# port_scan

Quick TCP port scanner with banner grabbing and concurrent scanning.

## Usage

```bash
python3 port_scan.py localhost
python3 port_scan.py example.com -p 80,443,8080
python3 port_scan.py 192.168.1.1 -p 1-1024 --threads 100
```

## Zero dependencies. Single file. Python 3.8+.
