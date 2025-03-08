import nmap
import sys
import json
from ipaddress import IPv4Network, AddressValueError
import argparse
import os
from tqdm import tqdm


def parse_arguments():
    parser = argparse.ArgumentParser(description="Enhanced Vulnerability Scanner")
    parser.add_argument("target_range", help="Target IP range (CIDR notation)")
    parser.add_argument("ports", help="Comma-separated list of ports to scan")
    parser.add_argument("output_file", help="Output file to save the scan results (JSON format)")
    parser.add_argument("--resume", action="store_true", help="Resume from cache file if available")
    args = parser.parse_args()
    return args


def validate_ports(ports_str):
    try:
        if '-' in ports_str:
            start, end = map(int, ports_str.split('-'))
            if start == 0 and end == 65535:
                return "1-65535"
            if start < 0 or end > 65535 or start > end:
                raise ValueError("Port range must be between 0 and 65535.")
            return list(range(start, end + 1))
        else:
            ports = [int(p.strip()) for p in ports_str.split(',')]
            if any(p < 0 or p > 65535 for p in ports):
                raise ValueError("Ports must be between 0 and 65535.")
            return ports
    except ValueError:
        raise ValueError("Invalid port format. Use a range (e.g., 0-65535) or list (e.g., 80,443).")


def surface_scan(ip_range):
    scanner = nmap.PortScanner()
    print(f"Performing surface scan on {ip_range} to identify active hosts...")
    scanner.scan(hosts=ip_range, arguments='-sn')  # Ping scan for active hosts
    active_hosts = [
        host for host in scanner.all_hosts() if scanner[host].get('status', {}).get('state') == 'up'
    ]
    for host in active_hosts:
        print(f"Active host found: {host}")
    return active_hosts


def scan_ports_in_chunks(target, ports, chunk_size=1000):
    scanner = nmap.PortScanner()
    scan_results = {'ip': target, 'open_ports': [], 'vulnerabilities': []}

    # Divide ports into smaller chunks
    for i in range(0, len(ports), chunk_size):
        chunk = ports[i:i + chunk_size]
        ports_to_scan = ','.join(map(str, chunk))

        try:
            print(f"Scanning {target} for port range: {chunk[0]}-{chunk[-1]}...")
            scanner.scan(target, ports_to_scan)

            if target in scanner.all_hosts():
                for port in scanner[target].get('tcp', {}):
                    state = scanner[target]['tcp'][port]['state']
                    if state == 'open':
                        scan_results['open_ports'].append(port)
                        scan_results['vulnerabilities'].extend(check_vulnerabilities(port))
        except Exception as e:
            print(f"Error while scanning target {target} for port range {chunk[0]}-{chunk[-1]}: {e}")

    return scan_results


def check_vulnerabilities(port):
    vulnerabilities = []
    if port == 21:
        vulnerabilities.append('Possible FTP vulnerability')
    elif port == 23:
        vulnerabilities.append('Possible Telnet vulnerability')
    elif port in [80, 443]:
        vulnerabilities.append('Possible web server vulnerability')
    return vulnerabilities


def save_results_to_file(results, filename):
    with open(filename, 'w') as outfile:
        json.dump(results, outfile, indent=4)


def load_cache(cache_file):
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as infile:
                data = infile.read().strip()
                return json.loads(data) if data else []
        except json.JSONDecodeError:
            print("Cache file is invalid. Starting fresh.")
    return []


def save_to_cache(cache_file, scanned_ips):
    temp_file = f"{cache_file}.tmp"
    with open(temp_file, 'w') as outfile:
        json.dump(scanned_ips, outfile, indent=4)
    os.replace(temp_file, cache_file)


def main():
    args = parse_arguments()
    try:
        ip_range = IPv4Network(args.target_range, strict=False)
    except AddressValueError:
        print("Invalid IP range. Use CIDR notation (e.g., 192.168.1.0/24).")
        sys.exit(1)

    try:
        ports = validate_ports(args.ports)
    except ValueError as e:
        print(e)
        sys.exit(1)

    cache_dir = os.path.join(os.getcwd(), 'cache')
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, 'cache_file.json')

    scanned_ips = load_cache(cache_file) if args.resume else []
    all_results = []

    active_hosts = surface_scan(str(ip_range))
    with tqdm(total=len(active_hosts)) as progress_bar:
        for host in active_hosts:  # Properly indented 'for' loop
            if host in scanned_ips:
                progress_bar.update(1)
                continue

            print(f"Scanning target {host} for open ports and vulnerabilities...")
            scan_result = scan_ports_in_chunks(host, list(range(1, 65536)))  # Full port range
            if scan_result:
                all_results.append(scan_result)
                scanned_ips.append(host)

            save_to_cache(cache_file, scanned_ips)
            progress_bar.update(1)

    print("Saving results to file...")
    save_results_to_file(all_results, args.output_file)
    print(f"Results saved to {args.output_file}.")
    if os.path.exists(cache_file):
        os.remove(cache_file)



if __name__ == "__main__":
    main()
