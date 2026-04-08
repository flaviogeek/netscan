import argparse
import csv
import json
import logging
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from queue import Queue
from typing import Dict, List, Optional

COMMON_PORTS: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 161: "snmp", 443: "https",
    3306: "mysql", 3389: "rdp", 5900: "vnc", 8080: "http-alt",
    5432: "postgresql", 27017: "mongodb", 6379: "redis", 9200: "elasticsearch",
}

TOP_PORTS = [80, 443, 22, 21, 25, 3389, 143, 110, 53, 23, 3306,
    8080, 139, 445, 5900, 8000, 8443, 1723, 111, 135, 993, 995, 179, 2049, 5060]

BANNER = r"""
  _______          __      _________                     
 \      \   _____/  |_   /   _____/ ____ _____    ____  
 /   |   \_/ __ \   __\  \_____  \_/ ___\\__  \  /    \ 
/    |    \  ___/|  |    /        \  ___/ / __ \|   |  \
\____|__  /\___  >__|   /_______  /\___  >____  /___|  /
        \/     \/               \/     \/ 
    Network Port Scanner v2.0 (Enhanced)
"""

class PortScanner:
    def __init__(self, timeout: float = 1.5, retries: int = 1, verbose: bool = False):
        self.timeout = timeout
        self.retries = retries
        self.verbose = verbose
        self.results: List[Dict] = []
        self.lock = threading.Lock()
        self.logger = logging.getLogger(self.__class__.__name__)

    def is_host_alive(self, host: str, port: int = 80) -> bool:
        """Verifica se o host está ativo."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port)) == 0
                if result:
                    self.logger.debug(f"Host {host} is alive (port {port} open)")
                return result
        except Exception as e:
            self.logger.error(f"Error checking host {host}: {e}")
            return False

    def resolve_target(self, target: str) -> str:
        """Resolve hostname para IP."""
        try:
            ip = socket.gethostbyname(target)
            self.logger.info(f"Resolved {target} to {ip}")
            return ip
        except socket.gaierror as e:
            self.logger.error(f"Unable to resolve {target}: {e}")
            raise ValueError(f"Invalid target: {target}")

    def grab_banner(self, host: str, port: int, timeout: Optional[float] = None) -> str:
        """Captura banner do serviço."""
        t = timeout or self.timeout
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(t)
                sock.connect((host, port))
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                data = sock.recv(1024)
                return data.decode(errors="ignore").strip()[:100].replace("\r\n", " ").replace("\n", " ")
        except (socket.timeout, OSError):
            return ""

    def scan_port(self, host: str, port: int) -> Optional[Dict]:
        """Escaneia uma porta com retry logic."""
        for attempt in range(self.retries):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    start_time = time.time()
                    result = sock.connect_ex((host, port))
                    duration = time.time() - start_time

                    if result == 0:
                        service = COMMON_PORTS.get(port, "unknown")
                        banner = self.grab_banner(host, port)
                        port_info = {
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": service,
                            "banner": banner,
                            "response_time": round(duration * 1000, 2),  # em ms
                        }
                        self.logger.debug(f"Found open port {port} on {host}")
                        return port_info
            except Exception as e:
                self.logger.debug(f"Attempt {attempt + 1}/{self.retries} failed for {host}:{port}: {e}")
                if attempt < self.retries - 1:
                    time.sleep(0.1)
        return None

    def worker(self, host: str, queue: Queue) -> None:
        """Worker thread para escanear portas."""
        while not queue.empty():
            port = queue.get()
            try:
                result = self.scan_port(host, port)
                if result:
                    with self.lock:
                        self.results.append(result)
            finally:
                queue.task_done()

    def scan(self, host: str, ports: List[int], threads: int) -> List[Dict]:
        """Executa o scan em um host."""
        self.results = []
        queue = Queue()
        
        for port in ports:
            queue.put(port)

        thread_list = []
        for _ in range(min(threads, len(ports), 256)):  # Limita a 256 threads
            t = threading.Thread(target=self.worker, args=(host, queue), daemon=True)
            t.start()
            thread_list.append(t)

        queue.join()
        for t in thread_list:
            t.join()

        return sorted(self.results, key=lambda x: x["port"])

def parse_ports(port_string: str) -> List[int]:
    """Parse de strings de portas (ex: 22,80,443,8000-8100)."""
    ports = set()
    try:
        for chunk in port_string.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                start_str, end_str = chunk.split("-", 1)
                start, end = int(start_str), int(end_str)
                if start < 1 or end > 65535 or start > end:
                    raise ValueError("Port range must be 1-65535 and start <= end")
                ports.update(range(start, end + 1))
            else:
                port = int(chunk)
                if port < 1 or port > 65535:
                    raise ValueError("Port must be between 1 and 65535")
                ports.add(port)
        return sorted(ports)
    except ValueError as e:
        raise ValueError(f"Invalid port specification: {e}")

def export_json(results: List[Dict], filename: str) -> None:
    """Exporta resultados em JSON."""
    output = {
        "timestamp": datetime.now().isoformat(),
        "ports_scanned": len(results),
        "open_ports": results
    }
    with open(filename, "w") as f:
        json.dump(output, f, indent=2)
    logging.getLogger(__name__).info(f"Results exported to {filename}")

def export_csv(results: List[Dict], filename: str) -> None:
    """Exporta resultados em CSV."""
    if not results:
        return
    
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    logging.getLogger(__name__).info(f"Results exported to {filename}")

def export_html(target: str, results: List[Dict], filename: str, elapsed: float) -> None:
    """Exporta resultados em HTML."""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Port Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .open {{ color: green; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Port Scan Report</h1>
    <p><strong>Target:</strong> {target}</p>
    <p><strong>Scan Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>Duration:</strong> {elapsed:.2f}s</p>
    <p><strong>Open Ports Found:</strong> {len(results)}</p>
    
    <table>
        <tr>
            <th>Port</th>
            <th>Protocol</th>
            <th>State</th>
            <th>Service</th>
            <th>Response Time (ms)</th>
            <th>Banner</th>
        </tr>
"""
    for r in results:
        html += f"""        <tr>
            <td>{r['port']}</td>
            <td>{r['protocol']}</td>
            <td class="open">{r['state']}</td>
            <td>{r['service']}</td>
            <td>{r.get('response_time', 'N/A')}</td>
            <td>{r['banner'] or '-'}</td>
        </tr>
"""
    html += """    </table>
</body>
</html>"""
    with open(filename, "w") as f:
        f.write(html)
    logging.getLogger(__name__).info(f"HTML report exported to {filename}")

def print_report(target: str, address: str, elapsed: float, results: List[Dict], total_ports: int) -> None:
    """Imprime relatório formatado."""
    print(f"\nNmap scan report for {target} ({address})")
    print(f"Host is up (approx. {elapsed:.2f}s latency).")
    print(f"Not shown: {total_ports - len(results)} closed/filtered ports\n")

    if results:
        print(f"{'PORT':<6}{'STATE':<8}{'SERVICE':<15}{'RESPONSE TIME':<15}{'BANNER'}")
        print("-" * 100)
        for r in results:
            banner = (r['banner'][:60] + "...") if len(r['banner']) > 60 else r['banner']
            print(f"{r['port']:<6}{r['state']:<8}{r['service']:<15}{r.get('response_time', 0):.2f}ms{' '*8}{banner}")
    else:
        print("All scanned ports are closed or filtered.")
    print(f"\nScan completed in {elapsed:.2f} seconds.")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced TCP port scanner with logging and export",
        epilog="Example: python network_scan_v2.py 192.168.1.1 -p 22,80,443 -t 50 --export json"
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
        help="Port range or list (e.g. 22,80,443,8000-8100). Default: 1-1024")
    parser.add_argument("-t", "--threads", type=int, default=50,
        help="Number of worker threads (default: 50, max: 256)")
    parser.add_argument("--top-ports", type=int, default=0,
        help="Scan top N most common ports instead of default range")
    parser.add_argument("--timeout", type=float, default=1.5,
        help="Socket timeout in seconds (default: 1.5)")
    parser.add_argument("--retries", type=int, default=1,
        help="Number of retries per port (default: 1)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--check-alive", action="store_true",
        help="Check if host is alive before scanning")
    parser.add_argument("--export", choices=["json", "csv", "html", "all"],
        help="Export results to file (json/csv/html/all)")
    parser.add_argument("-o", "--output", default="scan_results",
        help="Output filename prefix (default: scan_results)")

    args = parser.parse_args()

    logging.basicConfig(
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
        level=logging.DEBUG if args.verbose else logging.INFO
    )
    logger = logging.getLogger(__name__)

    print(BANNER)

    # Validações
    if args.threads < 1 or args.threads > 256:
        parser.error("Threads must be between 1 and 256")
    if args.retries < 1:
        parser.error("Retries must be >= 1")
    if args.timeout <= 0:
        parser.error("Timeout must be > 0")

    # Resolve target
    try:
        address = socket.gethostbyname(args.target)
    except socket.gaierror:
        parser.error(f"Unable to resolve target '{args.target}'")

    # Parse portas
    try:
        if args.top_ports > 0:
            if args.top_ports > len(TOP_PORTS):
                parser.error(f"--top-ports must be between 1 and {len(TOP_PORTS)}")
            ports = TOP_PORTS[:args.top_ports]
        else:
            ports = parse_ports(args.ports)
    except ValueError as e:
        parser.error(str(e))

    # Check host alive (opcional)
    if args.check_alive:
        logger.info(f"Checking if {args.target} is alive...")
        scanner = PortScanner(timeout=args.timeout, retries=args.retries, verbose=args.verbose)
        if not scanner.is_host_alive(address):
            logger.warning(f"Host {args.target} does not respond. Continuing anyway...")

    # Executa scan
    logger.info(f"Starting scan on {args.target} ({address}) with {args.threads} threads...")
    logger.info(f"Scanning {len(ports)} ports")

    start_time = time.time()
    scanner = PortScanner(timeout=args.timeout, retries=args.retries, verbose=args.verbose)
    results = scanner.scan(address, ports, args.threads)
    elapsed = time.time() - start_time

    # Imprime relatório
    print_report(args.target, address, elapsed, results, len(ports))

    # Export
    if args.export:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if args.export in ["json", "all"]:
            export_json(results, f"{args.output}_{timestamp}.json")
        if args.export in ["csv", "all"]:
            export_csv(results, f"{args.output}_{timestamp}.csv")
        if args.export in ["html", "all"]:
            export_html(args.target, results, f"{args.output}_{timestamp}.html", elapsed)

if __name__ == "__main__":
    main()
