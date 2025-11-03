#!/usr/bin/env python3
"""
pwner.py - Python rewrite of pwner.sh
Features:
 - argparse for CLI
 - subprocess calls with safe args
 - optional Kerberos (-k): getTGT via impacket-getTGT, export KRB5CCNAME
 - domain detection from `nxc ldap`
 - BloodHound collection using nxc (with Kerberos)
 - SMB share check (smbmap or smbclient)
 - Certipy run + JSON parsing
 - signal handling + cleanup
"""

import argparse, os, sys, re, json, tempfile, signal
from subprocess import run, CalledProcessError, DEVNULL
from pathlib import Path

# ANSI colors
RED = '\033[0;31m'; GREEN = '\033[0;32m'; BLUE = '\033[0;34m'; YELLOW = '\033[0;33m'; RESET = '\033[0m'

def status(ok, msg):
    prefix = f"{GREEN}[+]{RESET}" if ok else f"{RED}[-]{RESET}"
    print(f"{prefix} {msg}")

def run_cmd(cmd, desc=None, check=False):
    if desc: print(f"{BLUE}==> {desc}{RESET}")
    # cmd must be a list
    r = run(cmd, capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    if out:
        print(out.strip())
    if check and r.returncode != 0:
        raise CalledProcessError(r.returncode, cmd, output=r.stdout, stderr=r.stderr)
    return r

def which(binname: str) -> bool:
    """Return True if a binary is available in PATH."""
    try:
        # Linux / macOS way (uses built-in 'which' command)
        run(["which", binname],
                       stdout=DEVNULL,
                       stderr=DEVNULL,
                       check=True)
        return True
    except (CalledProcessError, FileNotFoundError):
        return False

def detect_domain_from_nxc(ip):
    if not which("nxc"):
        return None
    r = run(["nxc", "ldap", ip], capture_output=True, text=True)
    txt = (r.stdout or "") + (r.stderr or "")
    m = re.search(r'domain:([^\)\s]+)', txt)
    if m:
        return m.group(1)
    # fallback to any hostname.domain.tld
    m2 = re.search(r'([A-Za-z0-9._-]+\.[A-Za-z]{2,})', txt)
    if m2:
        return m2.group(1)
    return "UNKNOWN"

def get_tgt_impacket(domain, user, password, tmpdir):
    domain_up = domain.split('.', 1)[1].upper()
    status(True, f"Attempting impacket-getTGT for {domain_up}")
    outpath = Path(tmpdir) / "impacket_gettgt.out"
    # call impacket-getTGT safely
    r = run(["impacket-getTGT", f"{domain_up}/{user}:{password}"], capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    outpath.write_text(out)
    # try to find .ccache in output
    m = re.search(r'(/[^ \n]*\.ccache)', out)
    if m:
        cc = Path(m.group(1))
        if cc.exists():
            return cc
    # fallback: newest .ccache in cwd or /tmp
    candidates = list(Path.cwd().glob("*.ccache")) + list(Path("/tmp").glob("*.ccache"))
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    if candidates:
        return candidates[0]
    return None

def run_bloodhound_nxc(domain, user, password, ip, use_kerb, out_file):
    # domain should be FQDN like dc01.voleur.htb
    if not which("nxc"):
        status(False, "nxc not installed. Cannot run BloodHound via nxc")
        return False
    cmd = ["nxc", "ldap", domain]
    if use_kerb:
        cmd += ["-k"]
    else:
        cmd += ["-u", user, "-p", password]
    # nxc ldap FQDN -k -u 'USER' -p 'PASS' --dns-server IP -c All --bloodhound
    # include -u -p even with -k 
    if use_kerb:
        cmd += ["-u", user, "-p", password]
    cmd += ["--dns-server", ip, "-c", "All", "--bloodhound"]
    r = run(cmd, capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    Path(out_file).write_text(out)
    status(True, f"BloodHound collection saved to {out_file}")
    return True

def smb_enumeration(ip, user, password):
    if which("smbmap"):
        run_cmd(["smbmap", "-u", user, "-p", password, "-H", ip], "smbmap enumeration")
    elif which("smbclient"):
        run_cmd(["smbclient", "-L", f"//{ip}", "-U", f"{user}%{password}"], "smbclient list")
    else:
        status(False, "No SMB enumeration tool (smbmap/smbclient) available")

def run_certipy(user, password, ip, domain_upper, tmp_txt):
    if not which("certipy"):
        status(False, "certipy not installed; skipping cert scan")
        return None
    args = ["certipy", "find", "-vulnerable"]
    # If you want -k with certipy and -target FQDN:
    if os.environ.get("KRB5CCNAME"):
        args += ["-k", "-u", user, "-p", password, "-target", f"DC01.{domain_upper}"]
    else:
        args += ["-u", user, "-p", password, "-dc-ip", ip]
    r = run(args, capture_output=True, text=True)
    Path(tmp_txt).write_text((r.stdout or "") + (r.stderr or ""))
    # attempt to discover corresponding json: search cwd and /tmp
    for p in list(Path.cwd().glob("*Certipy*.json")) + list(Path("/tmp").glob("*Certipy*.json")):
        return str(p)
    return None

def parse_certipy_json(jsonpath):
    if not jsonpath:
        return
    try:
        j = json.loads(Path(jsonpath).read_text())
    except Exception as e:
        status(False, f"Failed to parse JSON: {e}")
        return
    cas = j.get("Certificate Authorities", {})
    if not cas:
        status(False, "No Certificate Authorities in JSON")
        return
    for k,v in cas.items():
        name = v.get("CA Name", k)
        print(f"{GREEN}[+] CA: {name}{RESET}")
        vulns = v.get("[!] Vulnerabilities", {})
        if not vulns:
            print(f"{YELLOW}    No vulnerabilities found{RESET}")
        else:
            for vuln_name, vuln_info in vulns.items():
                print(f"    {GREEN}VULN: {vuln_name}{RESET}")
                if isinstance(vuln_info, dict):
                    desc = vuln_info.get("Description") or vuln_info.get("description") or str(vuln_info)
                    print(f"      {YELLOW}{desc}{RESET}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip")
    parser.add_argument("-u","--user", required=True)
    parser.add_argument("-p","--pass", dest="passwd", required=True)
    parser.add_argument("-k","--kerb", action="store_true")
    parser.add_argument("-d", "--domain", help="Specify target domain FQDN (e.g. voleur.htb)")
    args = parser.parse_args()

    # tempdir auto cleaned on exit
    with tempfile.TemporaryDirectory(prefix="pwner.") as tmpdir:
        # simple signal handling: ensure cleanup
        def on_sig(signum, frame):
            status(False, f"Interrupted (signal {signum}), exiting.")
            sys.exit(1)
        signal.signal(signal.SIGINT, on_sig)
        signal.signal(signal.SIGTERM, on_sig)
    
        ip = args.ip; user = args.user; password = args.passwd 
        if args.domain:
            regexStr = re.compile(r'^[A-Za-z0-9-]+\.[A-Za-z0-9-]+\.[A-Za-z0-9-]+$') # Check if the domain is in the form of *.*.*
            if not regexStr.match(domain):
                status(False, f"Invalid domain: {args.domain}\nProvide the FQDN e.g. dc01.voleur.htb") 
            domain = args.domain
        else:
            domain = detect_domain_from_nxc(ip)
        status(True, f"Pinging {ip} ...")
        ping_res = run(["ping","-c","1","-W","2", ip], capture_output=True, text=True)
        if ping_res.returncode != 0:
            status(False, f"Host {ip} unreachable")
            sys.exit(1)

        if (domain):
            domain_upper = domain.upper()
        else:
            status(False, f"Couldn't find domain, consider specifying it with -d FQDN")
            sys.exit(1)
        status(True, f"Using domain: {domain}")

        # Kerberos TGT if requested
        if args.kerb:
            if not which("impacket-getTGT"):
                status(False, "impacket-getTGT not found; cannot get TGT")
                sys.exit(1)
            cc = get_tgt_impacket(domain, user, password, tmpdir)
            if not cc:
                status(False, "No .ccache found after impacket-getTGT; check output")
                print(Path(tmpdir).joinpath("impacket_gettgt.out").read_text())
                sys.exit(1)
            os.environ["KRB5CCNAME"] = str(cc)
            status(True, f"KRB5CCNAME set to {cc}")

            # run BloodHound collection via nxc per your command
            bh_out = Path(tmpdir) / "bloodhound_nxc.out"
            run_bloodhound_nxc(domain, user, password, ip, use_kerb=True, out_file=str(bh_out))

        # Try LDAP auth check via nxc (with Kerberos or creds)
        if which("nxc"):
            if args.kerb:
                r = run(["nxc", "ldap", ip, "-k"], capture_output=True, text=True)
            else:
                r = run(["nxc", "ldap", ip, "-u", user, "-p", password], capture_output=True, text=True)
            o = (r.stdout or "") + (r.stderr or "")
            print(o.strip())
            if r.returncode != 0 or ("denied" in o.lower() or "rejected" in o.lower()):
                status(False, "LDAP credentials rejected")
                sys.exit(1)
            status(True, "LDAP credentials confirmed (nxc)")
        else:
            status(False, "nxc not installed; skipping LDAP confirm")

        # SMB enumeration
        smb_enumeration(ip, user, password)

        # Certipy scan
        cert_txt = Path(tmpdir) / f"certipy_{user}.txt"
        json_path = run_certipy(user, password, ip, domain_upper, str(cert_txt))
        if json_path:
            parse_certipy_json(json_path)
        else:
            # parse txt fallback
            print(cert_txt.read_text() if cert_txt.exists() else "No certipy output")

        status(True, "Pwner finished successfully")

if __name__ == "__main__":
    main()
