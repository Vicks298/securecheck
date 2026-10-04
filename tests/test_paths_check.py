import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from checks.paths_check import check_paths
from helpers import serve, handler

HTML = {"Content-Type": "text/html"}
TEXT = {"Content-Type": "text/plain"}


def run(pki, routes):
    https = serve(handler(404, {}, routes), pki)
    return check_paths("localhost", https.server_port)


def titles(fs):
    return {(f.severity, f.title) for f in fs}


def test_nothing_exposed(pki):
    assert titles(run(pki, {})) == {("Info", "No exposed files found")}


def test_exposed_env_and_git_without_leaking_contents(pki):
    routes = {"/.env": (200, TEXT, b"DB_PASSWORD=hunter2\nAPI_KEY=abc123\n"),
              "/.git/HEAD": (200, TEXT, b"ref: refs/heads/main\n")}
    fs = run(pki, routes)
    assert ("Critical", "Settings file with secrets is public") in titles(fs)
    assert ("Critical", "Git repository is public") in titles(fs)
    everything = " ".join(str(f.to_dict()) for f in fs)
    assert "hunter2" not in everything and "abc123" not in everything


def test_home_page_returned_for_every_path_is_not_a_finding(pki):
    # A site that answers 200 with its home page for any address must not trigger false alarms.
    page = (200, HTML, b"<html><body>Welcome to our shop</body></html>")
    routes = {p: page for p in ("/.git/HEAD", "/.env", "/backup.zip", "/backup.sql", "/phpmyadmin/", "/wp-login.php")}
    assert titles(run(pki, routes)) == {("Info", "No exposed files found")}


def test_backups_and_admin_pages(pki):
    routes = {"/backup.zip": (200, {"Content-Type": "application/zip"}, b"PK\x03\x04rest"),
              "/backup.sql": (200, TEXT, b"CREATE TABLE users (id int);"),
              "/phpmyadmin/": (200, HTML, b"<title>phpMyAdmin</title>"),
              "/wp-login.php": (200, HTML, b"<input name='user_login'>")}
    t = titles(run(pki, routes))
    assert ("High", "Backup file is public") in t
    assert ("Critical", "Database backup is public") in t
    assert ("Medium", "Database admin page is public") in t
    assert ("Low", "WordPress login page is public") in t


def test_forbidden_is_not_exposed(pki):
    routes = {"/.env": (403, TEXT, b"DB_PASSWORD=x")}
    assert titles(run(pki, routes)) == {("Info", "No exposed files found")}


def test_https_down():
    t = titles(check_paths("localhost", 1, timeout=2))
    assert t == {("Info", "Exposed-file check could not complete")}
