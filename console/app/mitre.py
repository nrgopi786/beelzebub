"""MITRE ATT&CK classification for honeypot events.

A lightweight rule engine maps each attacker event (protocol + command/URI/credentials/
user-agent) to one or more ATT&CK techniques. Events are tagged at ingest with two keyword
arrays — `techniques` (IDs like "T1059.004") and `tactics` (tactic names) — so the store can
aggregate and filter an ATT&CK matrix. Technique names are resolved from TECHNIQUES here, so
documents stay small and the catalogue lives in one place.

Rules are deliberately conservative and honeypot-oriented; they are heuristics for triage,
not a definitive attribution.
"""
import re

# Ordered ATT&CK Enterprise tactics we assign (subset relevant to honeypot traffic).
TACTICS = ["Reconnaissance", "Initial Access", "Execution", "Persistence",
           "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
           "Lateral Movement", "Collection", "Command and Control", "Impact"]

# technique id -> (name, tactic)
TECHNIQUES = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1098.004": ("SSH Authorized Keys", "Persistence"),
    "T1222": ("File and Directory Permissions Modification", "Defense Evasion"),
    "T1070": ("Indicator Removal", "Defense Evasion"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1552": ("Unsecured Credentials", "Credential Access"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1016": ("System Network Configuration Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1613": ("Container and Resource Discovery", "Discovery"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
    "T1005": ("Data from Local System", "Collection"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1496": ("Resource Hijacking", "Impact"),
}


def _rx(pattern):
    return re.compile(pattern, re.IGNORECASE)


# (compiled regex, technique id) evaluated against the shell command
CMD_RULES = [
    (_rx(r"\b(wget|curl|tftp|ftpget|scp|sftp)\b|/dev/tcp/|\bnc\b.*-e|certutil.*-urlcache"), "T1105"),
    (_rx(r"xmrig|minerd|cpuminer|kinsing|kdevtmpfsi|kswapd0|stratum\+tcp|/xmr|donate\.v2"), "T1496"),
    (_rx(r"(cat|less|more|head|tail)\s+/etc/shadow|(cat|getent)\s.*passwd|/etc/shadow"), "T1003"),
    (_rx(r"\b(id|whoami|groups|logname)\b"), "T1033"),
    (_rx(r"\buname\b|/proc/(cpuinfo|version)|\blscpu\b|/etc/os-release|\bhostnamectl\b|\bfree\b|\blsb_release\b"), "T1082"),
    (_rx(r"\b(ifconfig|iwconfig|netstat|route|arp)\b|\bip\s+(a|addr|link|route)\b|\bss\b|/etc/resolv\.conf"), "T1016"),
    (_rx(r"\b(ps|top|htop|pgrep)\b|/proc/\d"), "T1057"),
    (_rx(r"\b(crontab|cron)\b|/etc/cron|systemctl.*timer"), "T1053.003"),
    (_rx(r"authorized_keys|\.ssh/|ssh-keygen|ssh-rsa\s"), "T1098.004"),
    (_rx(r"\b(chmod|chown|chattr)\b"), "T1222"),
    (_rx(r"history\s+-c|rm\s+-rf|\bshred\b|unset\s+HISTFILE|HISTFILE=/dev/null|>\s*/var/log|truncate\s+-s\s*0"), "T1070"),
    (_rx(r"base64\s+(-d|--decode)|\|\s*base64|xxd\s+-r|openssl\s+enc\s+-d|\beval\b"), "T1140"),
    (_rx(r"\b(docker|kubectl|crictl|podman)\b|docker\.sock"), "T1613"),
    (_rx(r"(cat|less|more)\s+.*(id_rsa|\.aws|\.env|credentials|\.git-credentials|\.htpasswd)"), "T1552"),
    (_rx(r"\b(find|locate)\b|\bls\s+-"), "T1083"),
]

# evaluated against "METHOD URI BODY" for HTTP
HTTP_RULES = [
    (_rx(r"\$\{jndi:|jndi:(ldap|rmi|dns)"), "T1190"),
    (_rx(r"\.\./|%2e%2e|\.%2e|/etc/passwd|/etc/shadow|c:\\windows"), "T1190"),
    (_rx(r"<script|onerror=|onload=|javascript:|%3cscript"), "T1190"),
    (_rx(r"union\s+select|'\s*or\s*'?1'?='?1|sleep\(\d|benchmark\(|information_schema|pg_sleep"), "T1190"),
    (_rx(r"/cgi-bin/|\(\)\s*\{|/bin/(ba)?sh"), "T1190"),
    (_rx(r"[;|`]\s*(wget|curl|bash|sh|nc|cat|id|whoami|ping)|\$\((wget|curl|id)"), "T1190"),
    (_rx(r"\.env|/\.git|/\.aws|id_rsa|\.ssh|/\.htpasswd|/config\.|\.sql\b|/backup|/dump"), "T1552"),
    (_rx(r"wp-login|xmlrpc\.php|/administrator|/user/login|/admin/login|/login\.action|j_spring_security"), "T1110"),
    (_rx(r"phpmyadmin|/wp-admin|/manager/html|/solr/|/actuator|/console|/\.well-known|/vendor/|/shell|/boaform"), "T1595"),
]

# evaluated against the User-Agent
UA_RULES = [
    (_rx(r"sqlmap|nikto|nuclei|acunetix|nessus"), "T1190"),
    (_rx(r"nmap|masscan|zgrab|zmap|dirbuster|gobuster|wpscan|python-requests|go-http-client|censys|shodan|libwww"), "T1595"),
]

# evaluated against the raw TCP payload (command)
TCP_RULES = [
    (_rx(r"CONFIG\s+SET|SLAVEOF|REPLICAOF|MODULE\s+LOAD|\beval\b|FLUSHALL|BGSAVE"), "T1210"),
]


def classify(doc: dict) -> tuple[list[str], list[str]]:
    """Return (technique_ids, tactic_names) for one event document."""
    if doc.get("source") == "browser":
        return [], []
    protocol = (doc.get("protocol") or "").upper()
    cmd = doc.get("command") or ""
    ids: set[str] = set()

    if doc.get("password") and protocol in ("SSH", "TELNET", "HTTP"):
        ids.add("T1110")

    if protocol in ("SSH", "TELNET") and cmd:
        ids.add("T1059.004")
        for rx, tid in CMD_RULES:
            if rx.search(cmd):
                ids.add(tid)

    if protocol == "HTTP":
        target = f"{doc.get('method', '')} {doc.get('uri', '')} {doc.get('body', '')}"
        matched = False
        for rx, tid in HTTP_RULES:
            if rx.search(target):
                ids.add(tid)
                matched = True
        for rx, tid in UA_RULES:
            if rx.search(doc.get("user_agent", "")):
                ids.add(tid)
                matched = True
        if not matched and doc.get("uri"):
            ids.add("T1595")

    if protocol == "TCP":
        for rx, tid in TCP_RULES:
            if rx.search(cmd):
                ids.add(tid)
        ids.add("T1046")

    ids &= set(TECHNIQUES)
    tactics = {TECHNIQUES[i][1] for i in ids}
    return sorted(ids), sorted(tactics, key=TACTICS.index)


def catalog() -> dict:
    """id -> {name, tactic}, plus tactic order, for the UI and assistant."""
    return {"techniques": {i: {"name": n, "tactic": t} for i, (n, t) in TECHNIQUES.items()},
            "tactics": TACTICS}


def name_of(tid: str) -> str:
    return TECHNIQUES.get(tid, (tid, ""))[0]
