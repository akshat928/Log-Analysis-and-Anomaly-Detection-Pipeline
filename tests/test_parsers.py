from log_pipeline.parsers import parse_access_line, parse_auth_line


def test_failed_password_invalid_user():
    line = "Oct 20 11:00:04 webserver sshd[4242]: Failed password for invalid user admin from 185.220.101.7 port 50001 ssh2"
    rec = parse_auth_line(line, 2026)
    assert rec["event"] == "failed_password"
    assert rec["user"] == "admin"
    assert rec["ip"] == "185.220.101.7"
    assert rec["timestamp"].hour == 11


def test_accepted_login():
    line = "Oct  5 09:12:00 webserver sshd[1111]: Accepted publickey for akshat from 10.0.0.12 port 52000 ssh2"
    rec = parse_auth_line(line, 2026)
    assert rec["event"] == "accepted_login"
    assert rec["user"] == "akshat"
    assert rec["timestamp"].day == 5


def test_sudo_command():
    line = "Oct 21 02:01:00 webserver sudo[6162]:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    rec = parse_auth_line(line, 2026)
    assert rec["event"] == "sudo_command"
    assert rec["user"] == "deploy"
    assert rec["command"] == "/bin/cat /etc/shadow"


def test_unknown_auth_line_returns_none():
    assert parse_auth_line("garbage", 2026) is None
    line = "Oct 20 08:00:00 webserver CRON[999]: pam_unix(cron:session): session closed for user root"
    assert parse_auth_line(line, 2026) is None


def test_access_line():
    line = '45.155.205.99 - - [20/Oct/2026:10:00:02 +0530] "GET /.env HTTP/1.1" 404 150 "-" "gobuster/3.6"'
    rec = parse_access_line(line)
    assert rec["ip"] == "45.155.205.99"
    assert rec["status"] == 404
    assert rec["path"] == "/.env"
    assert rec["agent"] == "gobuster/3.6"


def test_access_line_without_agent_and_dash_size():
    line = '1.2.3.4 - bob [20/Oct/2026:10:00:02 +0000] "POST /login HTTP/1.1" 302 -'
    rec = parse_access_line(line)
    assert rec["user"] == "bob"
    assert rec["size"] == 0
