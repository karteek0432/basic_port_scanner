import socket
import threading
import queue
import time
import ssl
from colorama import Fore, Style, init
import argparse

# Initialize colorama for cross-platform colored output
init(autoreset=True)

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"

def print_banner():
    banner = rf'''
{Fore.GREEN}  
_____   ____  _____ _______    _____  _____          _   _ _   _ ______ _____  
 |  __ \ / __ \|  __ \__   __|  / ____|/ ____|   /\   | \ | | \ | |  ____|  __ \ 
 | |__) | |  | | |__) | | |    | (___ | |       /  \  |  \| |  \| | |__  | |__) |
 |  ___/| |  | |  _  /  | |     \___ \| |      / /\ \ | . ` | . ` |  __| |  _  / 
 | |    | |__| | | \ \  | |     ____) | |____ / ____ \| |\  | |\  | |____| | \ \ 
 |_|     \____/|_|  \_\ |_|    |_____/ \_____/_/    \_\_| \_|_| \_|______|_|  \_\                                                   
{Style.RESET_ALL}'''

    print(banner)
    print(f"{Fore.MAGENTA}{'=' * 50}")
    print("                P O R T   S C A N N E R")
    print(f"{Fore.MAGENTA}{'=' * 50}\n")

def print_progress(scanned, total):
    percent = int((scanned / total) * 100)
    bar_length = 40
    filled_length = int(bar_length * percent // 100)
    bar = f'{Fore.GREEN}{"█" * filled_length}{Style.RESET_ALL}' + '░' * (bar_length - filled_length)
    print(f"\r[{bar}] {percent}% Complete", end="", flush=True)
    if scanned == total:
        print("\n")  # Move to next line after completion

def scan_port(ip, port, results, lock, total_ports, scanned_counter, progress_lock):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = get_service_name(port)
                if port == 443:
                    try:
                        context = ssl.create_default_context()
                        with context.wrap_socket(sock, server_hostname=ip) as ssock:
                            ssock.getpeercert()  # Forces SSL handshake
                            with lock:
                                results.append((port, "https"))
                    except Exception as e:
                        with lock:
                            results.append((port, f"https (error: {str(e).split('(')[0]})"))
                else:
                    with lock:
                        results.append((port, service))
    except Exception as e:
        pass
    finally:
        with progress_lock:
            scanned_counter[0] += 1
            print_progress(scanned_counter[0], total_ports)

def worker(ip, port_queue, results, lock, total_ports, scanned_counter, progress_lock):
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            break

        scan_port(ip, port, results, lock, total_ports, scanned_counter, progress_lock)
        port_queue.task_done()

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="TCP Port Scanner")
    parser.add_argument("target", nargs="?", help="Target IP address or domain name")
    parser.add_argument("-p", "--ports", choices=["known", "all"], default="known",
                        help="Port range: known (1-1024) or all (1-65535)")
    args = parser.parse_args()

    if not args.target:
        target = input(f"{Fore.YELLOW}[?] Enter target IP or domain: {Style.RESET_ALL}").strip()
    else:
        target = args.target

    try:
        ip = socket.gethostbyname(target)
        print(f"\n{Fore.GREEN}[✓] Resolved {target} to {ip}{Style.RESET_ALL}")
    except socket.gaierror:
        print(f"{Fore.RED}[✗] Invalid domain or IP address.{Style.RESET_ALL}")
        return

    print("\nSelect Port Range:")
    print(f"{Fore.CYAN}1. Well-Known Ports (1–1024){Style.RESET_ALL}")
    print(f"{Fore.CYAN}2. All Ports (1–65535){Style.RESET_ALL}")

    while True:
        choice = input(f"{Fore.YELLOW}[?] Enter option (1 or 2): {Style.RESET_ALL}").strip()
        if choice == "1":
            start_port, end_port = 1, 1024
            break
        elif choice == "2":
            start_port, end_port = 1, 65535
            break
        else:
            print(f"{Fore.RED}[✗] Invalid choice. Please enter '1' or '2'.{Style.RESET_ALL}")

    port_queue = queue.Queue()
    total_ports = end_port - start_port + 1
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    results = []
    lock = threading.Lock()
    scanned_counter = [0]
    progress_lock = threading.Lock()

    start_time = time.time()

    print(f"\n{Fore.CYAN}[→] Scanning {ip} from port {start_port} to {end_port}...{Style.RESET_ALL}")
    num_threads = min(80, total_ports)
    print(f"{Fore.MAGENTA}[★] Using {num_threads} threads...\n{Style.RESET_ALL}")

    threads = []
    try:
        for _ in range(num_threads):
            t = threading.Thread(
                target=worker,
                args=(ip, port_queue, results, lock, total_ports, scanned_counter, progress_lock),
                daemon=True
            )
            t.start()
            threads.append(t)

        port_queue.join()

        for t in threads:
            t.join(timeout=1)

    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}[!] Scan interrupted by user.{Style.RESET_ALL}")
        exit(0)

    duration = time.time() - start_time

    print(f"\n{Fore.GREEN}[✓] Scan completed in {duration:.2f} seconds.{Style.RESET_ALL}")

    if results:
        print(f"\n{Fore.CYAN}[+] Open ports on {target}:{Style.RESET_ALL}")
        for port, service in sorted(results):
            print(f"    → Port {Fore.CYAN}{port}{Style.RESET_ALL} ({service}) is OPEN")

        save_to_file = input(f"\n{Fore.YELLOW}[?] Save results to file? (y/n): {Style.RESET_ALL}").strip().lower()
        if save_to_file == 'y':
            filename = f"{target.replace('.', '_')}_open_ports.txt"
            with open(filename, 'w') as f:
                for port, service in sorted(results):
                    f.write(f"Port {port} ({service}) is OPEN\n")
            print(f"{Fore.GREEN}[✓] Results saved to {filename}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[✗] No open ports found.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()