#!/usr/bin/env python3

# SubSleuth: Passive subdomain enumeration tool
# Pulls from HackerTarget, crt.sh, URLScan.io, CertSpotter, Anubis/JLDC, AlienVault OTX.
# Requires: pip install requests
# 0xAmanita

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import socket
from collections import defaultdict

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HTTP_TIMEOUT = 15
DNS_TIMEOUT = 3
PROBE_TIMEOUT = 5
RESOLVE_WORKERS = 50

# sources
def source_hackertarget(domain):
    subs = set()
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=HTTP_TIMEOUT)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.strip().splitlines():
                name = line.split(",")[0].strip().lower()
                if name.endswith(domain):
                    subs.add(name)
    except requests.RequestException:
        pass
    return subs

def source_crtsh(domain):
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain):
                        subs.add(name)
    except (requests.RequestException, ValueError):
        pass
    return subs

def source_urlscan(domain):
    subs = set()
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            for result in r.json().get("results", []):
                name = result.get("page", {}).get("domain", "").strip().lower()
                if name.endswith(domain):
                    subs.add(name)
    except (requests.RequestException, ValueError):
        pass
    return subs

def source_certspotter(domain):
    subs = set()
    try:
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        r = requests.get(url, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("dns_names", []):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain):
                        subs.add(name)
    except (requests.RequestException, ValueError):
        pass
    return subs

def source_anubis(domain):
    subs = set()
    try:
        r = requests.get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            for name in r.json():
                name = name.strip().lower()
                if name.endswith(domain):
                    subs.add(name)
    except (requests.RequestException, ValueError):
        pass
    return subs

def source_otx(domain):
    subs = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        r = requests.get(url, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            for entry in r.json().get("passive_dns", []):
                name = entry.get("hostname", "").strip().lower()
                if name.endswith(domain):
                    subs.add(name)
    except (requests.RequestException, ValueError):
        pass
    return subs

SOURCES = {
    "HackerTarget": source_hackertarget,
    "crt.sh": source_crtsh,
    "URLScan.io": source_urlscan,
    "CertSpotter": source_certspotter,
    "Anubis/JLDC": source_anubis,
    "AlienVault OTX": source_otx,
}

# resolution + liveness
def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def dns_resolve(host):
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        infos = socket.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos if is_valid_ip(i[4][0])})
    except (socket.gaierror, socket.timeout, UnicodeError, OSError):
        return []

def http_probe(host):
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}", timeout=PROBE_TIMEOUT,
                              allow_redirects=True, verify=False, stream=True)
            r.close()
            return r.status_code
        except requests.RequestException:
            continue
    return None

def check_host(host):
    ips = dns_resolve(host)
    if not ips:
        return host, ips, None
    return host, ips, http_probe(host)

# core flow
def gather_subdomains(domain):
    found = defaultdict(set)
    sources_hit = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(SOURCES)) as pool:
        futures = {pool.submit(fn, domain): name for name, fn in SOURCES.items()}
        for fut in concurrent.futures.as_completed(futures):
            name = futures[fut]
            try:
                subs = fut.result()
            except Exception:
                subs = set()
            if subs:
                sources_hit.add(name)
            for s in subs:
                found[s].add(name)

    if domain not in found:
        found[domain].add("input")

    return found, sources_hit

def resolve_all(hosts):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=RESOLVE_WORKERS) as pool:
        futures = {pool.submit(check_host, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            host, ips, code = fut.result()
            results[host] = (ips, code)
    return results

def enumerate_domain(domain):
    found, sources_hit = gather_subdomains(domain)
    resolved_map = resolve_all(found.keys())

    rows = []
    unique_ips = set()
    resolved_count = 0

    for sub in sorted(found.keys()):
        ips, code = resolved_map.get(sub, ([], None))
        status = "resolved" if (ips and code is not None) else "unresolved"
        if status == "resolved":
            resolved_count += 1
            unique_ips.update(ips)
        rows.append({
            "subdomain": sub,
            "ip": ", ".join(ips) if ips else "-",
            "http_status": str(code) if code is not None else "-",
            "sources": ", ".join(sorted(found[sub])),
            "status": status,
        })

    summary = {
        "domain": domain,
        "total": len(rows),
        "resolved": resolved_count,
        "unresolved": len(rows) - resolved_count,
        "sources_hit": sorted(sources_hit),
        "unique_ips": len(unique_ips),
    }

    return rows, summary

# output
def print_table(rows):
    if not rows:
        print("No subdomains found.")
        return

    w_sub = max(len("Subdomain"), max(len(r["subdomain"]) for r in rows))
    w_ip = max(len("IP Address"), max(len(r["ip"]) for r in rows))
    w_http = max(len("HTTP"), max(len(r["http_status"]) for r in rows))
    w_src = max(len("Sources"), max(len(r["sources"]) for r in rows))
    w_status = max(len("Status"), max(len(r["status"]) for r in rows))

    header = (f'{"Subdomain".ljust(w_sub)}  {"IP Address".ljust(w_ip)}  {"HTTP".ljust(w_http)}  '
              f'{"Sources".ljust(w_src)}  {"Status".ljust(w_status)}')
    print(header)
    print("-" * len(header))
    for r in rows:
        print(f'{r["subdomain"].ljust(w_sub)}  {r["ip"].ljust(w_ip)}  {r["http_status"].ljust(w_http)}  '
              f'{r["sources"].ljust(w_src)}  {r["status"].ljust(w_status)}')

def print_summary(summary):
    print()
    print("Summary")
    print("-" * 40)
    print(f"Domain            : {summary['domain']}")
    print(f"Total subdomains  : {summary['total']}")
    print(f"Resolved          : {summary['resolved']}")
    print(f"Unresolved        : {summary['unresolved']}")
    print(f"Sources hit       : {len(summary['sources_hit'])}/{len(SOURCES)} ({', '.join(summary['sources_hit']) or '-'})")
    print(f"Unique IPs        : {summary['unique_ips']}")

def save_csv(rows, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["subdomain", "ip", "http_status", "sources", "status"])
        writer.writeheader()
        writer.writerows(rows)

def save_json(rows, summary, path):
    with open(path, "w") as f:
        json.dump({"summary": summary, "results": rows}, f, indent=2)

# entry point
def main():
    parser = argparse.ArgumentParser(description="Passive subdomain enumeration tool")
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("-o", "--output", help="Save results to a CSV file")
    parser.add_argument("-j", "--json", help="Save results to a JSON file")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    print(f"Enumerating subdomains for: {domain}\n")

    rows, summary = enumerate_domain(domain)
    print_table(rows)
    print_summary(summary)

    if args.output:
        save_csv(rows, args.output)
        print(f"\nSaved CSV to {args.output}")
    if args.json:
        save_json(rows, summary, args.json)
        print(f"Saved JSON to {args.json}")

if __name__ == "__main__":
    main()
