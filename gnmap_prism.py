#!/usr/bin/env python3

import argparse
import os
import sys
import re
from collections import defaultdict
from pathlib import Path
import datetime
import ipaddress

BANNER = """
========================================
        gnmap_prism.py
   Nmap -oG Log Processor & Analyzer
========================================
  by Ivan Spiridonov / https://xbz0n.sh
"""

PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    500: "ike", 513: "rlogin", 514: "remoteshell", 587: "smtp-submission",
    636: "ldaps", 873: "rsync", 989: "ftps-data", 990: "ftps",
    992: "telnets", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc", 5901: "vnc-1",
    6000: "x11", 6001: "x11-1", 6379: "redis", 8000: "http-alt", 8080: "http-alt",
    8443: "https-alt", 9100: "jetdirect", 9200: "elasticsearch", 9300: "elasticsearch-node",
    11211: "memcached", 27017: "mongodb", 27018: "mongodb-alt"
}
TOOL_TARGETS_TCP = {
    'testssl': {443, 8443, 990, 992, 993, 995, 465, 636},
    'ftp': {21}, 'ssh': {22}, 'telnet': {23}, 'smb': {445, 139}, 'rdp': {3389},
    'http': {80, 8000, 8080},
}
TESTSSL_FORMAT = "{ip}:{port}"
DEFAULT_TARGET_FORMAT = "{ip}"
WEB_PORTS_GENERIC = {80, 443, 8000, 8080, 8443}
SMB_PORTS_GENERIC = {445, 139}

def get_service_label(port, proto):
    service_name = PORT_SERVICE_MAP.get(port)
    if service_name: suffix = f"-{proto}" if proto != 'tcp' or port in [53] else ""; return f"{service_name}{suffix}"
    else: return f"{port}-{proto}"

def parse_subnet_scope(scope_list):
    parsed_networks, invalid_scopes = [], []
    for scope in scope_list:
        try: network = ipaddress.ip_network(scope, strict=False); parsed_networks.append(network)
        except ValueError:
            try: ip = ipaddress.ip_address(scope); network = ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False); parsed_networks.append(network)
            except ValueError: invalid_scopes.append(scope)
    if invalid_scopes: print(f"Warning: Could not parse as IP/CIDR: {', '.join(invalid_scopes)}", file=sys.stderr)
    return sorted(list(set(parsed_networks))), invalid_scopes

def infer_subnets(ip_list, prefix=24):
    if not ip_list: return []
    subnets = set()
    for ip_str in ip_list:
        try: ip = ipaddress.ip_address(ip_str); network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False); subnets.add(network)
        except ValueError: continue
    return sorted(list(subnets))

def extract_scope_from_gnmap_header(infile):
    try:
        with open(infile, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.startswith('# Nmap') and ' as: ' in line:
                    try:
                        command_part = line.split(' as: ', 1)[1].strip(); tokens = command_part.split()[1:]
                        targets = []; skip_next = False; found_iL = False
                        nmap_opts_with_args = {'-p','-g','--source-port','-S','-e','-oN','-oX','-oS','-oG','-oA','--datadir','--servicedb','--versiondb','--host-timeout','--scan-delay','--max-scan-delay','--max-retries','--min-rate','--max-rate','-iL','--exclude','--excludefile','-sL','-sI','--script','--script-args','--stylesheet','-T','--ttl','--spoof-mac','--proxies','-D'}
                        nmap_opts_no_args = {'-n','-R','-sS','-sT','-sA','-sW','-sM','-sU','-sN','-sF','-sX','-sV','-O','-A','-6','-v','-vv','-d','-d','-Pn','-PS','-PA','-PU','-PE','-PP','-PM','-PO','-F','--fast','--resume','--open','--packet-trace','--iflist','--append-output','--reason','--webxml','--system-dns','--traceroute','--script-trace','--script-updatedb','--no-stylesheet','--stats-every'}
                        for i, token in enumerate(tokens):
                            if skip_next: skip_next = False; continue
                            if token in nmap_opts_with_args: skip_next = True; found_iL = (token == '-iL'); continue
                            if token in nmap_opts_no_args: continue
                            if token.startswith('-'):
                                if len(token) > 2 and not token[1].isdigit() and not token[1] == '-': continue
                                if '=' in token: continue
                                continue
                            targets.append(token)
                        if found_iL: return targets, "Found -iL"
                        elif targets: return targets, "Success"
                        else: return [], "Failed"
                    except Exception as parse_error: print(f"Warning: Error parsing Nmap command line: {parse_error}", file=sys.stderr); return [], "Failed"
            return [], "No Command Found"
    except Exception as e: print(f"Error reading file header {infile}: {e}", file=sys.stderr); return [], "Failed"

def parse_nmap_grepable(infile):
    all_hosts_status = {}; host_data_open = defaultdict(list); port_states_aggregate = defaultdict(int)
    current_host = None
    try:
        with open(infile, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') or not line: continue
                host_match = re.match(r"Host:\s*([\d\.]+)\s*(?:\((.*?)\))?\s*Status:\s*(.*)", line)
                if host_match:
                    current_host = host_match.group(1); status = host_match.group(3).strip().lower()
                    all_hosts_status[current_host] = status
                    if status == "up" and current_host in host_data_open: host_data_open[current_host] = []
                    continue
                if current_host and all_hosts_status.get(current_host) == "up" and "Ports:" in line:
                    port_info_str = line.split("Ports:", 1)[-1].strip()
                    port_entries = [p.strip() for p in port_info_str.split(',') if p.strip()]
                    for entry in port_entries:
                        parts = entry.split('/')
                        if len(parts) >= 5:
                            try:
                                port_state = parts[1].lower(); port_states_aggregate[port_state] += 1
                                if port_state == "open":
                                    port = int(parts[0]); proto = parts[2]; service = parts[4] if len(parts) > 4 and parts[4] else "unknown"
                                    host_data_open[current_host].append((port, proto, service))
                            except (ValueError, IndexError): print(f"Warning: Could not parse port entry: '{entry}' for host {current_host}", file=sys.stderr)
    except FileNotFoundError: print(f"Error: Input file not found: {infile}", file=sys.stderr); sys.exit(1)
    except Exception as e: print(f"Error reading or parsing file {infile}: {e}", file=sys.stderr); sys.exit(1)
    for host in host_data_open: host_data_open[host].sort(key=lambda x: x[0])
    return all_hosts_status, host_data_open, port_states_aggregate

def write_summary(host_data_open, all_hosts_status, outfile):
    print(f"[*] Writing summary to: {outfile}")
    hosts_with_open_ports = set(host_data_open.keys())
    up_hosts_total = {ip for ip, status in all_hosts_status.items() if status == 'up'}
    up_hosts_no_open_ports = sorted(list(up_hosts_total - hosts_with_open_ports))
    down_hosts = sorted([ip for ip, status in all_hosts_status.items() if status == 'down'])
    all_up_ips = list(hosts_with_open_ports) + up_hosts_no_open_ports
    max_host_len = max((len(ip) for ip in all_up_ips), default=15); max_host_len = max(max_host_len, 4)
    col1_width, col2_width, col3_width = max_host_len + 2, 14, 52
    header_footer = f"+{'-' * col1_width}+{'-' * col2_width}+{'-' * col3_width}+"
    title_line = f"| {'HOST'.ljust(col1_width-1)}| {'OPEN PORT'.ljust(col2_width-1)}| {'PROTOCOL - SERVICE'.ljust(col3_width-1)}|"
    with open(outfile, 'w') as f:
        f.write("# gnmap_prism.py - Scan Summary\n"); f.write(f"# Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"); f.write("=== Hosts with Open Ports ===\n")
        if hosts_with_open_ports:
            f.write(header_footer + '\n'); f.write(title_line + '\n')
            for host in sorted(list(hosts_with_open_ports)):
                ports = host_data_open[host]
                if not ports: continue
                f.write(header_footer + '\n'); first_port = True
                for port, proto, service in ports:
                    host_str = host if first_port else ""; port_str = f"{port}/{proto}"; service_str = service[:col3_width-6] + "..." if len(service) > col3_width - 3 else service
                    f.write(f"| {host_str.ljust(col1_width-1)}| {port_str.ljust(col2_width-1)}| {service_str.ljust(col3_width-1)}|\n"); first_port = False
            f.write(header_footer + '\n')
        else: f.write("No hosts found with open ports.\n")
        f.write("\n=== Hosts Up, No Open Ports Detected ===\n")
        if up_hosts_no_open_ports: f.write(f"(Found {len(up_hosts_no_open_ports)} host(s) responding but with no open ports reported)\n"); [f.write(f"- {host}\n") for host in up_hosts_no_open_ports]
        else: f.write("All 'Up' hosts had open ports reported, or no 'Up' hosts found.\n")
        f.write("\n=== Hosts Reported as Down ===\n")
        if down_hosts: f.write(f"(Found {len(down_hosts)} host(s) not responding to probes)\n"); [f.write(f"- {host}\n") for host in down_hosts]
        else: f.write("No hosts reported as 'Down'.\n")

def write_split_files(host_data_open, outdir, rename_files):
    print(f"[*] Writing split host files to: {outdir}/"); port_to_hosts = defaultdict(list)
    for host, ports in host_data_open.items(): [port_to_hosts[(port, proto)].append(host) for port, proto, _ in ports]
    created_files = []
    for (port, proto), hosts in port_to_hosts.items():
        label = get_service_label(port, proto) if rename_files else f"{port}-{proto}"; filename = outdir / f"{label}-hosts.txt"; created_files.append(filename.name)
        print(f"  - Writing {len(hosts)} host(s) to {filename.name}")
        with open(filename, 'w') as f: [f.write(host + '\n') for host in sorted(hosts)]
    return created_files

def write_generic_url_files(host_data_open, outdir):
    web_urls, smb_urls = [], []; web_file, smb_file = outdir / "web-urls.txt", outdir / "smb-urls.txt"
    for host, ports in host_data_open.items():
        for port, proto, _ in ports:
            if proto == 'tcp':
                if port in WEB_PORTS_GENERIC: scheme = "https" if port in [443, 8443] else "http"; port_str = f":{port}" if port not in [80, 443] else ""; web_urls.append(f"{scheme}://{host}{port_str}/")
                if port in SMB_PORTS_GENERIC: smb_urls.append(f"smb://{host}/")
    files_created = {}
    if web_urls: print(f"[*] Writing {len(web_urls)} generic URLs to: {web_file}"); files_created['web'] = True; open(web_file, 'w').write('\n'.join(url for url in sorted(list(set(web_urls)))) + '\n')
    if smb_urls: print(f"[*] Writing {len(smb_urls)} generic URLs to: {smb_file}"); files_created['smb'] = True; open(smb_file, 'w').write('\n'.join(url for url in sorted(list(set(smb_urls)))) + '\n')
    return files_created.get('web', False), files_created.get('smb', False)

def write_tool_target_files(host_data_open, outdir):
    print(f"[*] Writing tool-specific target files to: {outdir}/"); targets = defaultdict(list)
    for host, ports in host_data_open.items():
        for port, proto, _ in ports:
            if proto != 'tcp': continue
            for tool_name, target_ports in TOOL_TARGETS_TCP.items():
                if port in target_ports: fmt = TESTSSL_FORMAT if tool_name == 'testssl' else DEFAULT_TARGET_FORMAT; targets[tool_name].append(fmt.format(ip=host, port=port))
    created_files = []
    for tool_name, target_list in targets.items():
        if target_list:
            filename = outdir / f"{tool_name}-targets.txt"; unique_targets = sorted(list(set(target_list)))
            print(f"  - Writing {len(unique_targets)} target(s) to {filename.name}"); open(filename, 'w').write('\n'.join(target for target in unique_targets) + '\n'); created_files.append(filename.name)
    return created_files

def write_live_hosts(all_hosts_status, outfile):
    up_hosts = sorted([ip for ip, status in all_hosts_status.items() if status == 'up'])
    if not up_hosts: return False
    print(f"[*] Writing {len(up_hosts)} live hosts to: {outfile}")
    open(outfile, 'w').write('\n'.join(host for host in up_hosts) + '\n'); return True

def write_segmentation_report(all_hosts_status, host_data_open, port_states_aggregate, scope_source_description, target_scope_list, source_ip, outfile):
    print(f"[*] Writing technical segmentation report to: {outfile}")
    hosts_with_open_ports_set = set(host_data_open.keys())
    total_hosts_scanned = len(all_hosts_status); total_hosts_up = 0; total_hosts_down = 0; total_up_no_open = 0
    subnet_stats = defaultdict(lambda: {'total': 0, 'up': 0, 'up_no_open': 0})
    hosts_in_scope = set()
    target_networks_parsed, non_network_targets = parse_subnet_scope(target_scope_list)
    for host, status in all_hosts_status.items():
        is_up = (status == 'up'); has_no_open = is_up and (host not in hosts_with_open_ports_set)
        if is_up: total_hosts_up += 1; total_up_no_open += has_no_open
        else: total_hosts_down += 1
        matched_network = None
        if target_networks_parsed:
            try:
                host_ip_obj = ipaddress.ip_address(host)
                for net in sorted(target_networks_parsed, key=lambda x: x.prefixlen, reverse=True):
                    if host_ip_obj in net: matched_network = net; hosts_in_scope.add(host); break
            except ValueError: matched_network = 'Invalid IP Found'
        key = matched_network if matched_network else 'Other (Not in Defined Scope)'
        subnet_stats[key]['total'] += 1
        if is_up: subnet_stats[key]['up'] += 1; subnet_stats[key]['up_no_open'] += has_no_open
    with open(outfile, 'w') as f:
        f.write("##################################################\n"); f.write("# gnmap_prism.py - Network Segmentation Summary\n"); f.write("##################################################\n"); f.write(f"# Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("=== Scan Parameters ===\n"); f.write(f"Source IP Address    : {source_ip if source_ip else 'Not Specified'}\n"); f.write(f"Target Scope Source  : {scope_source_description}\n"); f.write("Target Scope Items   :\n")
        if target_scope_list: [f.write(f"  - {scope_item}\n") for scope_item in target_scope_list]
        else: f.write("  - None Specified or Determined\n")
        f.write("\n=== Overall Scan Statistics ===\n"); f.write(f"Total Hosts Scanned  : {total_hosts_scanned}\n"); f.write(f"  Hosts Up           : {total_hosts_up}\n"); f.write(f"  Hosts Down         : {total_hosts_down}\n")
        f.write("Aggregate Port States:\n")
        if port_states_aggregate: states_str = ", ".join(f"{k.capitalize()}: {v}" for k, v in sorted(port_states_aggregate.items())); f.write(f"  {states_str}\n")
        else: f.write("  No port state information found.\n")
        f.write(f"Total 'Up' Hosts w/No Open Ports: {total_up_no_open}\n\n")
        f.write("=== Per-Network Segmentation Summary ===\n")
        if target_networks_parsed or 'Other (Not in Defined Scope)' in subnet_stats or 'Invalid IP Found' in subnet_stats:
            max_net_len = max((len(str(k)) for k in subnet_stats.keys()), default=18); max_net_len = max(max_net_len, 18)
            col_net, col_tot, col_up, col_iso = max_net_len + 1, 18, 10, 24
            header = f"{'Target Network'.ljust(col_net)}{'Total Hosts Scnd'.ljust(col_tot)}{'Hosts Up'.ljust(col_up)}{'Hosts Up w/ No Open Ports'.ljust(col_iso)}"; separator = f"{'-' * col_net}{'-' * col_tot}{'-' * col_up}{'-' * col_iso}"
            f.write(header + "\n"); f.write(separator + "\n")
            for key in sorted(subnet_stats.keys(), key=lambda x: str(x)):
                stats = subnet_stats[key]; f.write(f"{str(key).ljust(col_net)}{str(stats['total']).ljust(col_tot)}{str(stats['up']).ljust(col_up)}{str(stats['up_no_open']).ljust(col_iso)}\n")
        else: f.write("No network scope defined or determined; cannot provide per-network breakdown.\n"); f.write(f"Overall statistics indicate {total_up_no_open} 'Up' hosts were found with no open ports.\n")
        f.write("\n=== Final Conclusion ===\n"); f.write(f"Scan identified {total_up_no_open} host(s) responding from source '{source_ip if source_ip else 'Unknown'}' "); f.write("that did not have detectable 'open' ports within the scan configuration.\n"); f.write("This data can be used to evaluate network segmentation effectiveness for the scanned services.\n")
        f.write("####################### END REPORT #######################\n")

def main():
    parser = argparse.ArgumentParser(
        description=BANNER + "\nProcesses Nmap grepable (-oG) logs for analysis and reporting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Example Usage:
  ./gnmap_prism.py scan.gnmap -o results --source-ip 192.168.0.5 --gen-tools --segmentation
  ./gnmap_prism.py scan.gnmap --scope-file targets.txt --segmentation"""
    )

    parser.add_argument("input_file", help="Your grepable Nmap file (-oG output).")
    parser.add_argument("--out-dir", "-o", help="Custom output directory. Default: gnmap_prism_results-YYYY-MM-DD-HH-MM-SS/", default=None)
    parser.add_argument("--source-ip", help="Source IP address used for the Nmap scan.")
    scope_group = parser.add_mutually_exclusive_group()
    scope_group.add_argument("--scope", help="Manually define target scope (comma-separated). Overrides automatic.")
    scope_group.add_argument("--scope-file", help="Manually define target scope from a file. Overrides automatic.")
    parser.add_argument("--no-summary", action="store_true", help="Do not create summary.txt.")
    parser.add_argument("--no-split", action="store_true", help="Do not create [port/service]-hosts.txt files.")
    parser.add_argument("--no-rename", action="store_true", help="Use port numbers for split file names.")
    parser.add_argument("--no-generic-urls", action="store_true", help="Do not create generic web-urls.txt/smb-urls.txt.")
    parser.add_argument("--no-up", action="store_true", help="Do not create up-hosts.txt.")
    parser.add_argument("--gen-tools", action="store_true", help="Generate tool-specific target files.")
    parser.add_argument("--segmentation", action="store_true", help="Generate technical segmentation-report.txt.")
    parser.add_argument("--force", action="store_true", help="Allow overwriting files if output directory exists.")

    args = parser.parse_args()

    print(BANNER)

    input_file = Path(args.input_file)
    if not input_file.is_file(): print(f"Error: Input file not found: {input_file}", file=sys.stderr); sys.exit(1)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    output_dir_default_name = f"gnmap_prism_results-{timestamp}"
    output_dir = Path(output_dir_default_name) if args.out_dir is None else Path(args.out_dir) if args.out_dir != '.' else Path.cwd()
    output_dir_exists = output_dir.exists()

    if args.out_dir != '.':
        try: output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e: print(f"Error: Could not create output directory {output_dir}: {e}", file=sys.stderr); sys.exit(1)
    elif output_dir_exists and not output_dir.is_dir(): print(f"Error: Output path {output_dir} exists but is not a directory.", file=sys.stderr); sys.exit(1)
    if output_dir_exists and not args.force and args.out_dir is None: print(f"Warning: Default output directory '{output_dir}' already exists. Use --force or --out-dir.", file=sys.stderr)
    elif output_dir_exists and not args.force and args.out_dir is not None and args.out_dir != '.': print(f"Warning: Output directory '{output_dir}' already exists. Use --force.", file=sys.stderr)

    target_scope_list = []
    scope_source_description = "Not Specified"
    if args.scope: target_scope_list = [s.strip() for s in args.scope.split(',') if s.strip()]; scope_source_description = "User Defined (Command Line)"
    elif args.scope_file:
        try:
            with open(args.scope_file, 'r') as f: target_scope_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]; scope_source_description = f"User Defined (File: {args.scope_file})"
        except FileNotFoundError: print(f"Warning: Scope file not found: {args.scope_file}", file=sys.stderr); scope_source_description = "User Defined (File Not Found!)"
        except Exception as e: print(f"Warning: Error reading scope file {args.scope_file}: {e}", file=sys.stderr); scope_source_description = "User Defined (File Error!)"
    else:
        print("[*] Attempting automatic scope extraction...")
        extracted_targets, status = extract_scope_from_gnmap_header(input_file)
        if status == "Success": target_scope_list = extracted_targets; scope_source_description = "Automatic (Command Line)"; print(f"[*] Auto-extracted targets: {', '.join(target_scope_list)}")
        elif status == "Found -iL": scope_source_description = "Automatic (Command Line - Used -iL)"; print(f"[*] Nmap used '-iL'. Cannot auto-determine full scope. Targets found: {', '.join(extracted_targets)}"); target_scope_list = extracted_targets
        elif status == "No Command Found": scope_source_description = "Not Determined (No Command Found)"; print("[*] Auto-extraction failed: Nmap command not found.")
        else: scope_source_description = "Not Determined (Extraction Failed)"; print("[*] Auto-extraction failed: Could not parse command.")

    print("--- Processing Details ---")
    print(f"Input File:  {input_file}")
    print(f"Output Path: {output_dir.resolve()}")
    if args.source_ip: print(f"Source IP:   {args.source_ip}")
    print(f"Scope Source:{scope_source_description}")
    if target_scope_list: print(f"Scope Items: {len(target_scope_list)}")
    print("Functions Enabled:")
    if not args.no_up: print("- Create up-hosts.txt")
    if not args.no_summary: print("- Create summary.txt")
    if not args.no_split: print(f"- Create split *-hosts.txt files{' (renamed)' if not args.no_rename else ' (port numbers)'}")
    if not args.no_generic_urls: print("- Create generic web-urls.txt / smb-urls.txt")
    if args.gen_tools: print("- Create tool-specific target files (*-targets.txt)")
    if args.segmentation: print("- Create technical segmentation-report.txt")
    print("-" * 24 + "\n")

    print("[*] Parsing Nmap file...")
    all_hosts_status, host_data_open, port_states_aggregate = parse_nmap_grepable(input_file)
    print(f"[*] Parsed {len(all_hosts_status)} total hosts entries.")
    if not all_hosts_status: print("[!] No host entries found. Exiting."); sys.exit(0)
    print(f"[*] Found {len(host_data_open)} hosts with open ports.")
    print(f"[*] Aggregate port states found: {dict(port_states_aggregate)}")

    results_summary = defaultdict(list); files_created_count = 0
    if not args.no_up:
        if write_live_hosts(all_hosts_status, output_dir / "up-hosts.txt"): results_summary["info"].append("up-hosts.txt"); files_created_count += 1
    if not args.no_summary:
        write_summary(host_data_open, all_hosts_status, output_dir / "summary.txt"); results_summary["info"].append("summary.txt"); files_created_count += 1
    if not args.no_split and host_data_open:
        split_files = write_split_files(host_data_open, output_dir, not args.no_rename); results_summary["split"] = split_files; files_created_count += len(split_files)
    if not args.no_generic_urls and host_data_open:
        web_created, smb_created = write_generic_url_files(host_data_open, output_dir)
        if web_created: results_summary["generic_urls"].append("web-urls.txt"); files_created_count += 1
        if smb_created: results_summary["generic_urls"].append("smb-urls.txt"); files_created_count += 1
    if args.gen_tools and host_data_open:
        tool_files = write_tool_target_files(host_data_open, output_dir); results_summary["tool_targets"] = tool_files; files_created_count += len(tool_files)
    if args.segmentation:
        write_segmentation_report(all_hosts_status, host_data_open, port_states_aggregate, scope_source_description, target_scope_list, args.source_ip, output_dir / "segmentation-report.txt")
        results_summary["info"].append("segmentation-report.txt"); files_created_count += 1

    print("\n" + "="*15 + "[ Processing Complete ]" + "="*14)
    if output_dir_exists and args.out_dir is None: print(f"Note: Default output directory '{output_dir}' existed or was created.")
    elif output_dir_exists and args.out_dir is not None and args.out_dir != '.': print(f"Note: Output directory '{output_dir}' already existed.")
    print(f"Total output files generated: {files_created_count} in '{output_dir.resolve()}'")
    if results_summary["info"]: print(f"- Info/Report Files: {', '.join(results_summary['info'])}")
    if results_summary["generic_urls"]: print(f"- Generic URL Files: {', '.join(results_summary['generic_urls'])}")
    if results_summary["split"]: print(f"- Split Host Files: {len(results_summary['split'])} created (e.g., {results_summary['split'][0]}...)")
    if results_summary["tool_targets"]: print(f"- Tool Target Files: {', '.join(results_summary['tool_targets'])}")
    if files_created_count == 0: print("No output files were generated based on selected options and input data.")
    print("="*53 + "\n")

if __name__ == "__main__":
    main()