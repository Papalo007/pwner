#!/usr/bin/env python3
"""
pwner.py - Python rewrite of pwner.sh
Features:
 - a lot
"""
#TODO: Add automatic ESC exploitation 
#TODO: Add mssql exploitation

import argparse, os, sys, re, json, tempfile, signal, shlex, shutil
from subprocess import run, CalledProcessError, DEVNULL, CompletedProcess
from pathlib import Path

# ANSI colors
RED = '\033[0;31m'; GREEN = '\033[0;32m'; BLUE = '\033[0;34m'; YELLOW = '\033[0;33m'; RESET = '\033[0m'; BOLD = "\033[1m"

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

def get_tgt_impacket(domain, user, password, tmpdir):
    domain_up = domain.upper()
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

def detect_domain_from_nxc(ip):
    if not which("nxc"):
        status(False, "NetExec is not installed bruh I'm terminating ts")
        sys.exit(1)
    r = run(["nxc", "ldap", ip], capture_output=True, text=True)
    txt = (r.stdout or "") + (r.stderr or "")
    m = re.search(r'domain:([^\)\s]+)', txt)
    if m:
        return m.group(1)
    # fallback to any hostname.domain.tld
    m2 = re.search(r'([A-Za-z0-9._-]+\.[A-Za-z]{2,})', txt)
    if m2:
        return m2.group(1)
    return None

def run_bloodhound_nxc(fqdn, user, password, ip, use_kerb):
    if not which("nxc"):
        status(False, "NetExec not installed. Cannot run BloodHound via nxc")
        sys.exit(1)
    cmd = ["nxc", "ldap", fqdn]
    domain = fqdn.split(".", 1)[1]
    if use_kerb:
        cmd += ["-k"]
    cmd += ["-u", user, "-p", password, "-d", domain, "--dns-server", ip, "-c", "All", "--bloodhound"]
    r = run(cmd, capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")

    # Get zip path

    m = re.search(r'(/home/[^/\s]+/\.nxc/logs/[^\s"]+\.zip)', out)
    if not m:
        status(False, "Could not find BloodHound zip path in nxc output:")
        print(out)
        sys.exit(1)

    src = Path(m.group(1))
    if not src.exists():
        status(False, f"Reported zip path does not exist: {src}")
        sys.exit(1)

    dest = Path(f"./{domain}_{user}_bhcol.zip")
    # replace existing dest 
    try:
        if dest.exists():
            dest.unlink()
        shutil.move(str(src), str(dest))
    except Exception as e:
        status(False, f"Failed to move zip: {e}")
        sys.exit(1)

    status(True, f"BloodHound collection saved to {dest}")
    return True

def smb_enumeration(ip, user, password, fqdn=None):
    if not which("nxc"):
        status(False, "NetExec isn't installed (how bro)")
        sys.exit(1)
    print(f"{BLUE} => Enumerating SMB Shares...{RESET}")
    testing = run(
        ["nc", "-vz", ip, "445", "-w", "1"],
        capture_output=True,   # captures both stdout and stderr
        text=True,             # returns strings, not bytes
        timeout=5
    )

    out = (testing.stdout or "") + (testing.stderr or "")
    if "open" not in out.lower():
        status(False, "SMB doesn't seem to be open. Skipping..")
        return None
    if fqdn:
        out = run(["nxc", "smb", fqdn, "-k", "-u", user, "-p", password, "--shares"], capture_output=True, text=True)
        loggedonout = run(["nxc", "smb", fqdn, "-k", "-u", user, "-p", password, "--loggedon-users"], capture_output=True, text=True)
        genKrb5 = run(["nxc", "smb", fqdn, "-k", "-u", user, "-p", password, "--generate-krb5-file", "krb5.conf"], capture_output=True, text=True)
    else:
        out = run(["nxc", "smb", ip, "-u", user, "-p", password, "--shares"], capture_output=True, text=True)
        loggedonout = run(["nxc", "smb", ip, "-u", user, "-p", password, "--loggedon-users"], capture_output=True, text=True)
        genKrb5 = run(["nxc", "smb", ip, "-u", user, "-p", password, "--generate-krb5-file", "krb5.conf"], capture_output=True, text=True)
    print_clean(out.stdout)
    combined_log = (loggedonout.stdout or "") + (loggedonout.stderr or "")
    if "rpc_s_access_denied" in combined_log.lower():
        status(False, "Couldn't enum logged-on users using smb")
    else:
        lines = combined_log.splitlines(keepends=True)
        result = ''.join(lines[2:])
        status(True, "\nPossibly found logged-on users:")
        print(result)
    print(f"{YELLOW}[!]{RESET} Generated krb5 config. Set the environment variable:\nexport KRB5_CONFIG=krb5.conf")
    if fqdn:
        check_nxc_vulns(ip, user, password, fqdn)
    else:
        check_nxc_vulns(ip, user, password)

def print_clean(text):
    # accept CompletedProcess or string
    if isinstance(text, CompletedProcess):
        text = text.stdout or ""
    elif text is None:
        text = ""
    elif not isinstance(text, str):
        text = str(text)

    # Remove the "SMB fqdn port role" prefix from each line
    lines = []
    for ln in text.splitlines():
        no_prefix = re.sub(r'^[A-Z]+\s+\S+\s+\d+\s+\S+\s+', '', ln)
        # skip purely-empty lines
        if no_prefix.strip():
            lines.append(no_prefix.rstrip())

    if not lines:
        return

    # Try to find the header line (contains both 'Share' and 'Permissions')
    header_idx = None
    for i, ln in enumerate(lines):
        if re.search(r'\bShare\b', ln, re.IGNORECASE) and re.search(r'\bPermissions\b', ln, re.IGNORECASE):
            header_idx = i
            break
        # fallback: detect separator like "-----"
        if re.search(r'^\s*-{3,}\s+', ln):
            header_idx = max(0, i-1)  # include the line before the separator (likely header) if exists
            break

    if header_idx is not None:
        # keep everything from header onward (removes the initial noise)
        lines = lines[header_idx:]
    else:
        # otherwise, filter out explicit noise lines like "[*]" or "[+]"
        lines = [ln for ln in lines if not re.match(r'^\s*\[[\*\+!]', ln)]

    # Split rows into columns by 2+ spaces (keeps single-space data intact)
    rows = [re.split(r'\s{2,}', ln.strip()) for ln in lines if ln.strip()]

    if not rows:
        return

    # Normalize number of columns to 3 (Share, Permissions, Remark)
    for r in rows:
        while len(r) < 3:
            r.append('')

    # Compute column widths (based on content, but don't count ANSI codes)
    def visible_len(s: str) -> int:
        return len(re.sub(r'\033\[[0-9;]*m', '', s))

    col_widths = [0, 0, 0]
    for r in rows:
        for i in range(3):
            col_widths[i] = max(col_widths[i], visible_len(r[i]))

    # Print with alignment. Header (first row) printed raw (no coloring).
    print()  # blank line before table
    for idx, cols in enumerate(rows):
        share, perms, remark = cols[0], cols[1], cols[2]

        # If this is the header row (detect "Share" in first column), don't color
        is_header = bool(re.search(r'\bShare\b', share, re.IGNORECASE) and re.search(r'\bPermissions\b', perms, re.IGNORECASE)) \
                    or re.match(r'^\s*-{3,}\s*$', share)

        if is_header:
            share_s = share
            perms_s = perms
        else:
            share_s = f"{BOLD}{share}{RESET}" if share else ''
            perms_s = f"{YELLOW}{perms}{RESET}" if perms else ''

        # pad considering visible length (so ANSI codes don't break alignment)
        pad_share = col_widths[0] - visible_len(share)
        pad_perms = col_widths[1] - visible_len(perms)

        print(f"    {share_s}{' ' * pad_share}   {perms_s}{' ' * pad_perms}   {remark}")

def run_certipy(user, password, ip, domain_upper, tmp_txt):
    if not which("certipy"):
        status(False, "bro download certipy wtf")
        sys.exit(1)
    args = ["certipy", "find", "-vulnerable"]
    # If you want -k with certipy and -target FQDN:
    if os.environ.get("KRB5CCNAME"):
        args += ["-k", "-u", user, "-p", password, "-dc-ip", ip, "-target", f"{domain_upper}"]
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

def check_nxc_vulns(ip, user, password, fqdn=None):
    if fqdn:
        out = run(["nxc", "smb", fqdn, "-k", "-u", user, "-p", password, "-M", "coerce_plus"], capture_output=True, text=True)
    else:
        out = run(["nxc", "smb", ip, "-u", user, "-p", password, "-M", "coerce_plus"], capture_output=True, text=True)
    lines = out.stdout.splitlines()
    capture = False
    vuln_lines = []
    for line in lines:
        if capture:
            vuln_lines.append(line)
        elif "SMB" in line and f"\\{user}:" in line:
            capture = True  # start capturing after this line

    vuln_output = "\n".join(vuln_lines)
    if vuln_output.strip():
        status(True, "Found potential vulnerabilities:")
        s_lines = vuln_output.splitlines()
        skip_re = re.compile(r'Error in PrinterBug module: DCERPC Runtime Error: code: 0x16c9a0d6 - ept_s_not_registered')

        out_lines = [L for L in s_lines if not skip_re.search(L)]
        clean = "\n".join(out_lines)
        print(f"{YELLOW}{BOLD}{clean.strip()}{RESET}")
    else:
        status(False, "Didn't get a hit on any coerce vulnerabilities.")



def start(ip):
    print(f"{BLUE} => Pinging {ip}...{RESET}")
    ping_res = run(["ping","-c","1","-W","2", ip], capture_output=True, text=True)
    if ping_res.returncode != 0:
        status(False, f"Host {ip} unreachable")
        sys.exit(1)
    print(f"Sync times if you haven't already:\nfaketime \"$(ntpdate -q {ip} | cut -d ' ' -f 1,2)\" zsh\n")
    testing = run(
        ["nc", "-vz", ip, "445", "-w", "1"],
        capture_output=True,  
        text=True,             
        timeout=5
    )
    out = (testing.stdout or "") + (testing.stderr or "")
    if "open" not in out.lower():
        status(False, "SMB doesn't seem to be open.")
    else:
        print(f"{BLUE} => Checking SMB")
        smbcom = run(["nxc", "smb", ip], capture_output=True, text=True)
        domain = detect_domain_from_nxc(ip)
        cmd = f"dig +short ANY @{shlex.quote(ip)} {shlex.quote(domain)} | grep {shlex.quote(domain)} | head -n1 | sed 's/\\.$//'"
        res = run(cmd, shell=True, capture_output=True, text=True)
        fqdn = res.stdout.strip() or None
        status(True, f"Found domain: {domain} and FQDN: {fqdn}")
        if "NTLM:False" in smbcom.stdout:
            print(f"{YELLOW} [!] NTLM Authentication is disabled, use Kerberos!{RESET}")
        else:
            smbanonym = run(["nxc", "smb", ip, "-u", "", "-p", ""], capture_output=True, text=True)
            if "[+]" in smbanonym.stdout:
                print(f"{GREEN}[+] Anonymous login is enabled!{RESET}")
                enumShares = run(["nxc", "smb", ip, "-u", "", "-p", "", "--shares"], capture_output=True, text=True)
                if "Error enumerating shares: STATUS_ACCESS_DENIED" not in enumShares.stdout:
                    linesSh = enumShares.stdout.splitlines()
                    rest = "\n".join(linesSh[2:])
                    print(rest)
                else:
                    status(False, "Couldn't enumerate shares - Access denied")
                enumUsers = run(["nxc", "smb", ip, "-u", "", "-p", "", "--users"], capture_output=True, text=True)
                linesUs = enumUsers.stdout.splitlines()
                if len(linesUs) > 2:
                    status(True, "Potentially got a hit on users:\n")
                    restUs = "\n".join(linesUs[2:])
                    print(restUs)
                else:
                    status(False, "Couldn't enumerate users")
                enumPassPol = run(["nxc", "smb", ip, "-u", "", "-p", "", "--pass-pol"], capture_output=True, text=True)
                linesPP = enumPassPol.stdout.splitlines()
                if len(linesPP) > 2:
                    status(True, "Potentially got a hit on password policy:\n")
                    restPP = "\n".join(linesPP[2:])
                    print(restPP)
                else:
                    status(False, "Couldn't enumerate password policy")
                out = run(["nxc", "smb", ip, "-u", "", "-p", "", "-M", "coerce_plus"], capture_output=True, text=True)
                lines = out.stdout.splitlines()
                capture = False
                vuln_lines = []
                for line in lines:
                    if capture:
                        vuln_lines.append(line)
                    elif "SMB" in line and f"[+] {fqdn.split('.', 1)[1]}\\:" in line:
                            capture = True  # start capturing after this line

                vuln_output = "\n".join(vuln_lines)
                if vuln_output.strip():
                    status(True, "Found potential vulnerabilities:")
                    s_lines = vuln_output.splitlines()
                    skip_re = re.compile(r'Error in PrinterBug module: DCERPC Runtime Error: code: 0x16c9a0d6 - ept_s_not_registered')

                    out_lines = [L for L in s_lines if not skip_re.search(L)]
                    clean = "\n".join(out_lines)
                    print(f"{YELLOW}{BOLD}{clean.strip()}{RESET}")
                else:
                    status(False, "Didn't get a hit on any coerce vulnerabilities.")
                
    # Continue after finishing SMB
    testing = run(
        ["nc", "-vz", ip, "1433", "-w", "1"],
        capture_output=True,  
        text=True,             
        timeout=5
    )
    print(f"{BLUE} => Enumerating MSSQL{RESET}")
    out = (testing.stdout or "") + (testing.stderr or "")
    if "open" not in out.lower():
        status(False, "MSSQL doesn't seem to be open.")
    # TODO: add an else and start working on mssql exploitation
    # TODO: Also add other stuff like NFS, FTP, WMI etc.


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip")
    parser.add_argument("-u","--user")
    parser.add_argument("-p","--pass", dest="passwd")
    parser.add_argument("-k","--kerb", action="store_true")
    parser.add_argument("-d", "--domain", help="Specify target domain FQDN (e.g. voleur.htb)")
    parser.add_argument("--start", action="store_true")
    args = parser.parse_args()

    if not args.start:
            if not args.user or not args.passwd:
                parser.error("{RED} [-]{RESET} You need to provide a username and pass with -u and -p when not using --start")
    
    # tempdir auto cleaned on exit
    with tempfile.TemporaryDirectory(prefix="pwner.") as tmpdir:
        # simple signal handling: ensure cleanup
        def on_sig(signum, frame):
            status(False, f"Interrupted (signal {signum}), exiting.")
            sys.exit(1)
        signal.signal(signal.SIGINT, on_sig)
        signal.signal(signal.SIGTERM, on_sig)
    
        ip = args.ip; user = args.user; password = args.passwd 
        
        if args.start:
            start(ip)
            print(f"{GREEN} ------- Pwner finished succesfully! -------{RESET}")
            sys.exit(0)

        print(f"{BLUE} => Pinging {ip}...{RESET}")
        ping_res = run(["ping","-c","1","-W","2", ip], capture_output=True, text=True)
        if ping_res.returncode != 0:
            status(False, f"Host {ip} unreachable")
            sys.exit(1)

        regexStr = re.compile(r'^[A-Za-z0-9-]+\.[A-Za-z0-9-]+\.[A-Za-z0-9-]+$') # Check if the domain is in the form of *.*.*
        if args.domain and not regexStr.match(args.domain):
            status(False, f"Invalid domain: {args.domain}\nProvide the FQDN e.g. dc01.voleur.htb") 
        elif args.domain:
            fqdn = args.domain
            domain = fqdn.split(".", 1)[1]
        else:
            domain = detect_domain_from_nxc(ip)
            cmd = f"dig +short ANY @{shlex.quote(ip)} {shlex.quote(domain)} | grep {shlex.quote(domain)} | head -n1 | sed 's/\\.$//'"
            res = run(cmd, shell=True, capture_output=True, text=True)
            fqdn = res.stdout.strip() or None
            if not fqdn:
                status(False, "Failed to get FQDN, consider specifying it with -d")
                sys.exit(1)
            else:
                status(True, f"Found FQDN: {fqdn}\nUsing Domain: {domain}")

        # Kerberos TGT if requested
        if which("nxc") and not args.kerb:
            if args.kerb:
                r = run(["nxc", "ldap", ip, "-k"], capture_output=True, text=True)
            else:
                r = run(["nxc", "ldap", ip, "-u", user, "-p", password], capture_output=True, text=True)
            o = (r.stdout or "") + (r.stderr or "")
            if r.returncode != 0 or ("[-]" in o):
                status(False, "LDAP credentials rejected")
                sys.exit(1)
            status(True, "LDAP credentials confirmed (nxc)")
        elif not which("nxc"):
            status(False, "bro download netexec smh")
            sys.exit(1)

        if args.kerb:
            if not which("impacket-getTGT"):
                status(False, "impacket-getTGT not found; cannot get TGT")
                sys.exit(1)
            cc = get_tgt_impacket(domain, user, password, tmpdir)
            if not cc:
                if "kerberos sessionerror: krb_ap_err_skew(clock skew too great)" in Path(tmpdir).joinpath("impacket_gettgt.out").read_text().lower():
                    status(False, "Yo you forgot the clock skew bud")
                    sys.exit(1)
                status(False, "No .ccache found after impacket-getTGT; check output") 
                print(Path(tmpdir).joinpath("impacket_gettgt.out").read_text())
                sys.exit(1)
            os.environ["KRB5CCNAME"] = str(cc)
            status(True, f"KRB5CCNAME set to {cc}")

            # run BloodHound collection via nxc
            print(f"{BLUE} => Running Bloodhound Collection...{RESET}")
            run_bloodhound_nxc(fqdn, user, password, ip, use_kerb=True)
        else:
            print(f"{BLUE} => Running Bloodhound Collection...{RESET}")
            run_bloodhound_nxc(fqdn, user, password, ip, False)
        # Try LDAP auth check via nxc (with Kerberos or creds)

        # SMB enumeration
        if args.kerb:
            smb_enumeration(ip, user, password, fqdn)
        else:
            smb_enumeration(ip, user, password)

        # Certipy scan
        print(f"{BLUE} => Running Certipy...{RESET}")
        cert_txt = Path(tmpdir) / f"certipy_{user}.txt"
        json_path = run_certipy(user, password, ip, domain.upper(), str(cert_txt))
        if json_path:
            parse_certipy_json(json_path)
        else:
            if "[Errno 104]" in cert_txt.read_text():
                status(False, "Certipy connection got reset by peer (Errno 104)")
            else:
                status(False, "Certipy ran into an error:")
                print(cert_txt.read_text() if cert_txt.exists() else "No certipy output")

        print(f"{GREEN} ------- Pwner finished succesfully! -------{RESET}")

if __name__ == "__main__":
    main()
