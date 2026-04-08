import argparse
import json
import logging
import socket
import threading
import time
from datetime import datetime
from queue import Queue
from typing import Dict, List, Optional

COMMON_PORTS: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    161: "snmp",
    443: "https",
    3306: "mysql",
    3389: "rdp",
    5900: "vnc",
    8080: "http-alt",
    5432: "postgresql",
    27017: "mongodb",
    6379: "redis",
}

TOP_PORTS = [
    80, 443, 22, 21, 25, 3389, 143, 110, 53, 23, 3306,
    8080, 139, 445, 5900, 8000, 8443, 1723, 111, 135,
    993, 995, 179, 2049, 5060, 3128, 8888, 5901, 53
]

SOCKET_TIMEOUT = 1.5
RESULTS_LOCK = threading.Lock()

# Configurar logging
def setup_logging(verbose: bool = False) -> None:
    """Setup logging estruturado."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
        level=level
    )

logger = logging.getLogger(__name__)

BANNER = r"""
 
  _______          __      _________                     
 \      \   _____/  |_   /   _____/ ____ _____    ____  
 /   |   \_/ __ \   __\  \_____  \_/ ___\\__  \  /    \ 
/    |    \  ___/|  |    /        \  \___ / __ \|   |  \
\____|__  /\___  >__|   /_______  /\___  >____  /___|  /
        \/     \/               \/     \/     \/     \/ 
         Network port discovery  v1.0
 
"""


def parse_ports(port_string: str) -> List[int]:
    """Parse de strings de portas (ex: 22,80,443,8000-8100)."""
    ports: List[int] = []
    try:
        for chunk in port_string.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                start_str, end_str = chunk.split("-", 1)
                start = int(start_str)
                end = int(end_str)
                if start < 1 or end > 65535 or start > end:
                    raise ValueError("Port range must be 1-65535 and start <= end")
                ports.extend(range(start, end + 1))
            else:
                port = int(chunk)
                if port < 1 or port > 65535:
                    raise ValueError("Port must be between 1 and 65535")
                ports.append(port)
        return sorted(list(set(ports)))  # Remove duplicatas
    except ValueError as exc:
        raise ValueError(f"Invalid port specification: {exc}")



def resolve_target(target: str) -> str:
    """Resolve hostname para IP."""
    try:
        ip = socket.gethostbyname(target)
        logger.debug(f"Resolved {target} to {ip}")
        return ip
    except socket.gaierror as exc:
        logger.error(f"Unable to resolve target '{target}': {exc}")
        raise ValueError(f"Unable to resolve target '{target}': {exc}")


def grab_banner(host: str, port: int) -> str:
    """Captura banner do serviço."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            sock.connect((host, port))
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            data = sock.recv(1024)
            return data.decode(errors="ignore").strip().replace("\r", " ").replace("\n", " ")[:120]
    except (socket.timeout, OSError) as exc:
        logger.debug(f"Banner grab failed for {host}:{port}: {exc}")
        return ""


def scan_port(target: str, port: int, results: List[Dict], verbose: bool = False) -> None:
    """Escaneia uma porta TCP e captura banner."""
    if verbose:
        logger.debug(f"Scanning {target}:{port}/tcp...")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            start_time = time.time()
            result = sock.connect_ex((target, port))
            duration = time.time() - start_time

            if result == 0:
                service = COMMON_PORTS.get(port, "unknown")
                banner = grab_banner(target, port)
                with RESULTS_LOCK:
                    results.append({
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service,
                        "banner": banner,
                        "response_time": round(duration * 1000, 2),
                    })
                if verbose:
                    logger.info(f"Found open port {port}/tcp on {target}")
    except OSError as exc:
        logger.debug(f"Socket error scanning {target}:{port}: {exc}")


def worker(target: str, queue: Queue, results: List[Dict], verbose: bool = False) -> None:
    """Worker thread para escanear portas."""
    while not queue.empty():
        port = queue.get()
        try:
            scan_port(target, port, results, verbose=verbose)
        except Exception as exc:
            logger.error(f"Unexpected error in worker for {target}:{port}: {exc}")
        finally:
            queue.task_done()


def print_scan_report(target: str, address: str, start_time: float, results: List[Dict], total_ports: int) -> None:
    """Imprime relatório formatado."""
    elapsed = time.time() - start_time
    print(f"\nNmap scan report for {target} ({address})")
    print(f"Host is up (approx. {elapsed:.2f}s latency).\n")

    if results:
        print(f"Not shown: {total_ports - len(results)} closed/filtered ports\n")
        print(f"{'PORT':<6}{'STATE':<8}{'SERVICE':<15}{'RESP.TIME':<12}{'BANNER'}")
        print("-" * 100)
        for entry in results:
            banner_text = (entry["banner"][:50] + "...") if len(entry["banner"]) > 50 else entry["banner"]
            resp_time = entry.get("response_time", 0)
            print(f"{entry['port']:<6}{entry['state']:<8}{entry['service']:<15}{resp_time:.2f}ms{' '*6}{banner_text}")
    else:
        print("All scanned ports are filtered or closed.")

    print(f"\nScan completed in {elapsed:.2f} seconds.")


def run_scan(target: str, ports: List[int], threads: int, verbose: bool = False) -> List[Dict]:
    """Executa o scan em um host."""
    address = resolve_target(target)
    print(BANNER)
    logger.info(f"Starting scan on {target} ({address}) with {threads} threads...")
    if verbose:
        logger.debug(f"Scanning {len(ports)} ports")

    queue: Queue = Queue()
    results: List[Dict] = []
    total_ports = len(ports)
    start_time = time.time()

    for port in ports:
        queue.put(port)

    thread_list = []
    for _ in range(min(threads, total_ports)):
        t = threading.Thread(target=worker, args=(address, queue, results, verbose), daemon=True)
        t.start()
        thread_list.append(t)

    queue.join()
    for t in thread_list:
        t.join()

    results.sort(key=lambda x: x["port"])
    print_scan_report(target, address, start_time, results, total_ports)
    return results

# CLI
def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Lightweight nmap-style TCP port scanner",
        epilog="Example: python network_scan.py 192.168.1.1 -p 22,80,443,8000-8100 -t 80"
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Port range or list (e.g. 22,80,443,8000-8100). Default: 1-1024",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=50,
        help="Number of worker threads (default: 50, max: 256)",
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        default=0,
        help="Scan the top N most common ports instead of the default range",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show verbose scan progress",
    )
    parser.add_argument(
        "--export",
        choices=["json"],
        help="Export results to JSON file",
    )

    args = parser.parse_args()
    
    # Setup logging
    setup_logging(verbose=args.verbose)

    # Validação de threads
    if args.threads < 1 or args.threads > 256:
        parser.error("Threads must be between 1 and 256")

    # Parse ports
    if args.top_ports > 0:
        if args.top_ports > len(TOP_PORTS):
            parser.error(f"--top-ports must be between 1 and {len(TOP_PORTS)}")
        ports = TOP_PORTS[: args.top_ports]
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError as exc:
            parser.error(str(exc))

    # Execute scan
    try:
        results = run_scan(args.target, ports, args.threads, verbose=args.verbose)
        
        # Export JSON if requested
        if args.export == "json":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.json"
            output_data = {
                "timestamp": datetime.now().isoformat(),
                "target": args.target,
                "ports_scanned": len(ports),
                "open_ports": results
            }
            with open(filename, "w") as f:
                json.dump(output_data, f, indent=2)
            logger.info(f"Results exported to {filename}")
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return
    except Exception as exc:
        logger.error(f"Fatal error: {exc}")
        parser.error(str(exc))


if __name__ == "__main__":
    main()