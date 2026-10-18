#!/usr/bin/env python3
# CAI Blue/Red Team Pentest Framework © J~Net 2025

import argparse
import atexit
import difflib
import glob
import hashlib
import html as html_module
from http.cookies import SimpleCookie
import importlib
import importlib.util
import inspect
import json
import os
import random
import re
import shlex
import shutil
import socket
import ssl
import string
import subprocess
import sys
import time
import urllib.parse
import uuid
from datetime import datetime, timezone

import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    import readline
except ImportError:
    readline = None

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

CONFIG_FILE = "config.json"
MODULE_DIR = "modules"
LAST_CMD_FILE = "last.txt"
LOG_FILE = "scan.log"
REPORT_DIR = "reports"

DEFAULT_CONFIG = {
    "provider": "auto",
    "provider_url": "http://127.0.0.1:11434",
    "default_model": "deepseek-v4.1-flash:cloud",
    "api_key_env": "OPENCODE_API_KEY",
    "full_auto_next_step": 0,
    "nmap_args": "-sS -Pn -T4",
    "vuln_script": True,
    "scan_timeout": 300,
    "mode": 1,
    "username": "",
    "password": "",
    "security_level": "",
    "wordlist": "",
    "request_timeout": 10,
    "max_crawl_pages": 40,
    "max_injection_points": 40,
    "active_tests": True,
    "allow_upload": True,
    "history_file": ".cai_history",
    "user_agent": "CAI-Pentest/2.0",
}

OPENCODE_URL_MARKERS = ("opencode.ai", "zen/go")
OPENCODE_SESSION = str(uuid.uuid4())

cfg = dict(DEFAULT_CONFIG)
modules = {}
AI_ENABLED = True
AI_WARNED = False

SQL_ERROR_PATTERNS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "warning: mysqli",
    "mysqli_sql_exception",
    "mysql_fetch",
    "supplied argument is not a valid mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error at or near",
    "pg_query",
    "postgresql query failed",
    "sqlite error",
    "sqlite3.operationalerror",
    "ora-0",
    "sqlstate",
    "odbc sql server driver",
    "microsoft ole db provider",
    "invalid query",
    "sql command not properly ended",
)

COMMON_PATHS = (
    "admin/", "login.php", "logout.php", "setup.php", "phpinfo.php",
    "robots.txt", "sitemap.xml", ".git/HEAD", ".env", ".env.bak",
    "config.php", "config.php.bak", "backup.zip", "backup.tar.gz",
    "uploads/", "upload/", "hackable/uploads/", "vulnerabilities/",
    "instructions.php", "about.php", "security.php", "ids/", "docs/",
    "tests/", "db/", "index.php", "server-status", "phpmyadmin/",
    "api/", "graphql", "swagger.json", "openapi.json",
    "actuator/health", ".well-known/security.txt", "crossdomain.xml",
    "clientaccesspolicy.xml", "web.config", "Dockerfile", "compose.yml",
)

DEFAULT_USERS = ("admin", "root", "test", "user", "administrator", "guest")
DEFAULT_PASSWORDS = (
    "password", "admin", "123456", "12345678", "root", "test",
    "password1", "letmein", "qwerty", "admin123", "changeme",
)


def ensure_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        print("Created default config.json")


def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
    except Exception:
        data = {}
    for k, v in DEFAULT_CONFIG.items():
        if k not in data:
            data[k] = v
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=4)
    return data


def save_config():
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=4)


def save_last(cmd):
    with open(LAST_CMD_FILE, "w") as f:
        f.write(cmd)


def load_last():
    if not os.path.exists(LAST_CMD_FILE):
        return ""
    try:
        return open(LAST_CMD_FILE).read().strip()
    except OSError:
        return ""


def is_opencode_go(url=None):
    provider = str(cfg.get("provider", "auto")).strip().lower()
    if provider in ("opencode", "opencode-go", "opencode_go", "opencode.ai"):
        return True
    if provider in ("ollama", "local", "ollama-cloud"):
        return False
    u = str(url if url is not None else cfg.get("provider_url", "")).lower()
    return any(marker in u for marker in OPENCODE_URL_MARKERS)


def opencode_endpoint(url):
    base = str(url).strip().rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    if "opencode.ai" in base.lower() and not base.lower().endswith("/v1"):
        base += "/v1"
    return base + "/chat/completions"


def opencode_api_key():
    env_name = str(cfg.get("api_key_env", "OPENCODE_API_KEY")).strip() or "OPENCODE_API_KEY"
    return cfg.get("api_key") or os.environ.get(env_name, "")


def opencode_headers():
    headers = {
        "Content-Type": "application/json",
        "x-opencode-session": str(cfg.get("opencode_session") or OPENCODE_SESSION),
    }
    key = opencode_api_key()
    if key:
        headers["Authorization"] = "Bearer " + key
    return headers


def generate(prompt, model=None, url=None, timeout=60):
    global AI_WARNED
    if not AI_ENABLED:
        return "AI disabled"
    model = model or cfg.get("default_model", DEFAULT_CONFIG["default_model"])
    url = url or cfg.get("provider_url", DEFAULT_CONFIG["provider_url"])
    opencode = is_opencode_go(url)
    provider = "opencode-go" if opencode else "ollama"
    try:
        if opencode:
            if not opencode_api_key():
                return "opencode-go error: API key not set (set OPENCODE_API_KEY or api_key in config.json)"
            payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "stream": False}
            r = requests.post(opencode_endpoint(url), json=payload, headers=opencode_headers(), timeout=timeout)
            if r.status_code != 200:
                return "LLM error: " + r.text[:1000]
            j = r.json()
            try:
                return (j["choices"][0]["message"]["content"] or "").strip()
            except (KeyError, IndexError, TypeError, AttributeError):
                return "LLM error: unexpected opencode-go response: " + str(j)[:500]
        payload = {"model": model, "prompt": prompt, "stream": False}
        r = requests.post(f"{str(url).rstrip('/')}/api/generate", json=payload, timeout=timeout)
        if r.status_code != 200:
            return "LLM error: " + r.text[:1000]
        j = r.json()
        return j.get("response", "").strip()
    except Exception as e:
        if not AI_WARNED:
            print(f"[ai] {provider} unavailable: {e}")
            AI_WARNED = True
        return f"{provider} request failed: " + str(e)


def ai_ok(text):
    return bool(text) and not str(text).startswith(
        ("LLM error", "opencode-go error", "ollama request failed", "opencode request failed", "AI disabled")
    )


def ask_model(prompt):
    return generate(prompt)


def log_event(text):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {text}\n")
    except OSError:
        pass


def timestamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def rand_token(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def safe_print(text):
    try:
        print(text)
    except UnicodeEncodeError:
        print(str(text).encode("utf-8", "replace").decode("utf-8", "replace"))


class Findings:
    def __init__(self):
        self.items = []
        self._seen = set()

    def add(self, severity, title, url="", evidence="", detail=""):
        key = (title.lower(), url, evidence[:160])
        if key in self._seen:
            return
        self._seen.add(key)
        item = {
            "severity": severity.lower(),
            "title": title,
            "url": url,
            "evidence": evidence.strip(),
            "detail": detail.strip(),
        }
        self.items.append(item)
        line = f"[{severity.upper()}] {title}"
        if url:
            line += f" -> {url}"
        print(line)
        if evidence:
            one = " ".join(str(evidence).split())[:300]
            print(f"    evidence: {one}")
        log_event(line + (" | " + evidence[:300] if evidence else ""))

    def counts(self):
        out = {}
        for item in self.items:
            out[item["severity"]] = out.get(item["severity"], 0) + 1
        return out

    def render(self):
        if not self.items:
            return "No findings were confirmed."
        lines = []
        for item in self.items:
            lines.append(f"### {item['title']}")
            lines.append(f"- Severity: {item['severity']}")
            if item["url"]:
                lines.append(f"- URL: {item['url']}")
            if item["detail"]:
                lines.append(f"- Detail: {item['detail']}")
            if item["evidence"]:
                lines.append(f"- Evidence: `{item['evidence'][:500]}`")
            lines.append("")
        return "\n".join(lines)


class WebClient:
    def __init__(self, target, username=None, password=None, timeout=None):
        self.start_url = normalize_url(target)
        self.base_url = self.start_url
        self.origin = origin_of(self.start_url)
        self.username = username or cfg.get("username") or os.environ.get("CAI_USERNAME", "")
        self.password = password or cfg.get("password") or os.environ.get("CAI_PASSWORD", "")
        self.timeout = timeout or float(cfg.get("request_timeout", 10))
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": cfg.get("user_agent", "CAI-Pentest/2.0"),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.authenticated = False
        self.dvwa = False
        self.security = None
        self.last_login_error = ""
        self.cookies = {}
        self.cookie_meta = {}
        self.auth_cookie_meta = {}

    def absolute(self, href):
        if not href:
            return self.base_url
        href = str(href).strip()
        if href.startswith(("mailto:", "javascript:", "tel:", "data:")):
            return href
        return urllib.parse.urljoin(self.start_url, href).split("#")[0]

    def in_scope(self, url):
        try:
            a = urllib.parse.urlsplit(url)
            b = urllib.parse.urlsplit(self.origin)
            return (a.scheme, a.hostname, a.port or default_port(a.scheme)) == (
                b.scheme, b.hostname, b.port or default_port(b.scheme)
            )
        except ValueError:
            return False

    def cookie_header(self):
        return "; ".join(f"{name}={value}" for name, value in self.cookies.items())

    def store_cookies(self, response):
        if response is None:
            return
        try:
            headers = response.raw.headers.getlist("Set-Cookie")
        except Exception:
            headers = []
        if not headers:
            single = response.headers.get("Set-Cookie")
            headers = [single] if single else []
        for header in headers:
            jar = SimpleCookie()
            try:
                jar.load(header)
            except Exception:
                continue
            for name, morsel in jar.items():
                if morsel["max-age"] and str(morsel["max-age"]).isdigit() and int(morsel["max-age"]) <= 0:
                    self.cookies.pop(name, None)
                    self.cookie_meta.pop(name, None)
                    continue
                self.cookies[name] = morsel.value
                previous = self.cookie_meta.get(name, {})
                self.cookie_meta[name] = {
                    "secure": bool(morsel["secure"]) or bool(previous.get("secure")),
                    "httponly": bool(morsel["httponly"]) or bool(previous.get("httponly")),
                    "samesite": str(morsel["samesite"] or previous.get("samesite", "")).lower(),
                }

    def request(self, method, url, **kwargs):
        url = self.absolute(url)
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        kwargs.pop("allow_redirects", None)
        extra_headers = dict(kwargs.pop("headers", {}) or {})
        redirects = 0
        current_method = method
        current_url = url
        response = None
        while redirects <= 10:
            self.session.cookies.clear()
            headers = dict(extra_headers)
            cookie = self.cookie_header()
            if cookie:
                headers["Cookie"] = cookie
            try:
                response = self.session.request(
                    current_method, current_url, headers=headers,
                    allow_redirects=False, **kwargs,
                )
            except requests.RequestException as exc:
                print(f"[http] {current_method} {current_url} failed: {exc}")
                return None
            self.store_cookies(response)
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if location:
                    current_url = urllib.parse.urljoin(current_url, location)
                    if response.status_code in (301, 302, 303) and current_method.upper() == "POST":
                        current_method = "GET"
                        kwargs.pop("data", None)
                        kwargs.pop("files", None)
                    redirects += 1
                    continue
            break
        response.cai_url = current_url
        return response

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)


def default_port(scheme):
    return 443 if str(scheme).lower() == "https" else 80


def origin_of(url):
    p = urllib.parse.urlsplit(url)
    netloc = p.netloc
    return urllib.parse.urlunsplit((p.scheme, netloc, "/", "", "")).rstrip("/")


def normalize_url(target):
    text = str(target).strip().strip("'\"")
    if not re.match(r"^https?://", text, re.I):
        text = "http://" + text
    p = urllib.parse.urlsplit(text)
    if not p.netloc:
        raise ValueError("invalid target URL: " + str(target))
    path = p.path or "/"
    return urllib.parse.urlunsplit((p.scheme, p.netloc, path, p.query, ""))


def extract_url(text):
    match = re.search(r"https?://[^\s'\"<>]+", text, re.I)
    if match:
        return match.group(0).rstrip(").,;]`*").strip("`*")
    match = re.search(r"\b(?:localhost|[A-Za-z0-9._-]+\.(?:local|lan|test|internal|com|org|net|io|dev)|(?:\d{1,3}\.){3}\d{1,3}):\d{2,5}\b", text)
    if match:
        return match.group(0)
    return None


def extract_ip(text):
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return match.group(0) if match else None


def extract_credentials(text):
    creds = {}
    patterns = (
        r"--(?:user|username)\s+(\S+)",
        r"--(?:pass|password)\s+(\S+)",
    )
    for pattern in patterns:
        m = re.search(pattern, text, re.I)
        if m:
            key = "username" if "user" in pattern else "password"
            creds[key] = m.group(1).strip("'\"")
    m = re.search(r"username\s*[:=]?\s*(\S+)\s+password\s*[:=]?\s*(\S+)", text, re.I)
    if m:
        creds.setdefault("username", m.group(1).strip("'\".,;"))
        creds.setdefault("password", m.group(2).strip("'\".,;"))
    m = re.search(r"(?:login|account)\s+(?:as\s+)?(\S+)\s+(?:with\s+)?password\s+(\S+)", text, re.I)
    if m:
        creds.setdefault("username", m.group(1).strip("'\".,;"))
        creds.setdefault("password", m.group(2).strip("'\".,;"))
    return creds


def extract_security_level(text):
    m = re.search(r"(?:security(?:[ _-]?level)?|seclev)\s*[:=]?\s*(low|medium|high|impossible)\b", text, re.I)
    if m:
        return m.group(1).lower()
    m = re.search(r"--security\s+(low|medium|high|impossible)\b", text, re.I)
    return m.group(1).lower() if m else None


def html_of(response):
    if response is None:
        return ""
    try:
        return response.text
    except Exception:
        try:
            return response.content.decode("utf-8", "replace")
        except Exception:
            return ""


def content_type(response):
    if response is None:
        return ""
    return str(response.headers.get("content-type", "")).lower()


def normalize_text(text):
    text = str(text or "")
    text = re.sub(r"[0-9a-fA-F]{16,}", "HEX", text)
    text = re.sub(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b", "DATETIME", text)
    text = re.sub(r"\b\d{10,13}\b", "NUM", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def similarity(a, b):
    a = normalize_text(a)
    b = normalize_text(b)
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def extract_forms(html, page_url):
    if not BeautifulSoup or not html:
        return []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return []
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = (form.get("method") or "GET").upper()
        enctype = (form.get("enctype") or "").lower()
        inputs = []
        for tag in form.find_all(["input", "textarea", "select", "button"]):
            name = tag.get("name")
            if not name:
                continue
            if tag.name == "select":
                selected = tag.find("option", selected=True) or tag.find("option")
                value = selected.get("value", selected.text.strip()) if selected else ""
                typ = "select"
            elif tag.name == "textarea":
                value = tag.text or ""
                typ = "textarea"
            elif tag.name == "button":
                value = tag.get("value", tag.text or "")
                typ = (tag.get("type") or "button").lower()
            else:
                typ = (tag.get("type") or "text").lower()
                value = tag.get("value", "")
            inputs.append({"name": str(name), "type": typ, "value": str(value)})
        forms.append({
            "page_url": page_url,
            "action": str(action),
            "method": method,
            "enctype": enctype,
            "inputs": inputs,
        })
    return forms


def form_data(form, overrides=None, fill_blank=False):
    overrides = overrides or {}
    lower_overrides = {str(k).lower(): v for k, v in overrides.items()}
    data = {}
    for inp in form.get("inputs", []):
        name = inp["name"]
        typ = inp["type"]
        if typ == "file":
            continue
        if name in data:
            continue
        value = inp.get("value", "")
        if name.lower() in lower_overrides:
            value = lower_overrides[name.lower()]
        elif fill_blank and typ in ("text", "textarea", "search", "url", "email") and value == "":
            value = "test"
        data[name] = value
    return data


def find_login_form(forms):
    best = None
    for form in forms:
        has_password = any(i["type"] == "password" for i in form["inputs"])
        has_user = any(
            i["type"] in ("text", "email") and re.search(r"user|email|login|name", i["name"], re.I)
            for i in form["inputs"]
        )
        if has_password:
            if has_user:
                return form
            if best is None:
                best = form
    return best


def login_field_names(form):
    user_field = None
    pass_field = None
    for inp in form["inputs"]:
        if inp["type"] == "password" and not pass_field:
            pass_field = inp["name"]
        if inp["type"] in ("text", "email") and not user_field:
            if re.search(r"user|email|login|account", inp["name"], re.I):
                user_field = inp["name"]
    if not user_field:
        for inp in form["inputs"]:
            if inp["type"] in ("text", "email"):
                user_field = inp["name"]
                break
    return user_field, pass_field


def submit_form(client, form, overrides=None, files=None, fill_blank=False):
    action = str(form.get("action") or "").strip()
    if action in ("", "#") or action.startswith("#"):
        url = form.get("page_url")
    else:
        url = client.absolute(action)
    data = form_data(form, overrides, fill_blank=fill_blank)
    if form.get("method", "GET").upper() == "POST":
        return client.post(url, data=data, files=files)
    return client.get(url, params=data)


def attempt_login(client, verbose=True):
    if not client.username or not client.password:
        return False
    page = client.get(client.start_url)
    forms = extract_forms(html_of(page), client.start_url)
    form = find_login_form(forms)
    if not form:
        client.last_login_error = "no login form found"
        return False
    user_field, pass_field = login_field_names(form)
    if not user_field or not pass_field:
        client.last_login_error = "could not identify username/password fields"
        return False
    before = dict(client.cookies)
    response = submit_form(client, form, {user_field: client.username, pass_field: client.password})
    if response is None:
        return False
    body = html_of(response)
    final_path = urllib.parse.urlsplit(response.url).path.lower()
    login_path = urllib.parse.urlsplit(form["page_url"]).path.lower()
    has_password = any(
        i["type"] == "password" for form in extract_forms(body, response.url) for i in form["inputs"]
    )
    failure_words = ("incorrect", "invalid", "failed", "wrong password", "login failed")
    success = False
    if final_path != login_path and not any(w in body.lower() for w in failure_words):
        success = True
    if "logout" in body.lower() and not has_password:
        success = True
    if response.status_code in (200, 302) and "logout" in body.lower():
        success = True
    after = dict(client.cookies)
    if not success and after and after != before and "logout" in body.lower():
        success = True
    if success:
        client.authenticated = True
        client.auth_cookie_meta = dict(client.cookie_meta)
        client.start_url = response.url if response.url else client.start_url
        client.base_url = client.start_url
        if verbose:
            print(f"[auth] logged in as {client.username} at {response.url}")
        log_event(f"login success user={client.username} url={response.url}")
        return True
    client.last_login_error = "credentials rejected"
    if verbose:
        print(f"[auth] login failed for {client.username}: {client.last_login_error}")
    return False


def detect_dvwa(client, response=None):
    page = response if response is not None else client.get(client.start_url)
    body = html_of(page).lower()
    if "damn vulnerable web application" in body or "dvwa" in body:
        client.dvwa = True
        return True
    security = client.get(client.absolute("security.php"))
    return "dvwa" in html_of(security).lower()


def get_dvwa_security(client):
    response = client.get(client.absolute("security.php"))
    body = html_of(response)
    m = re.search(r"<select[^>]*name=['\"]security['\"][^>]*>(.*?)</select>", body, re.I | re.S)
    if m:
        selected = re.search(r"<option[^>]*selected[^>]*value=['\"]([^'\"]+)", m.group(1), re.I)
        if selected:
            return selected.group(1).lower()
        selected = re.search(r"<option[^>]*value=['\"]([^'\"]+)['\"][^>]*selected", m.group(1), re.I)
        if selected:
            return selected.group(1).lower()
    m = re.search(r"Security Level:\s*</em>\s*([a-z]+)", body, re.I)
    return m.group(1).lower() if m else None


def set_dvwa_security(client, level):
    level = str(level).lower()
    if level not in ("low", "medium", "high", "impossible"):
        print("[dvwa] invalid security level")
        return False
    page_url = client.absolute("security.php")
    page = client.get(page_url)
    forms = extract_forms(html_of(page), page_url)
    form = next((f for f in forms if any(i["name"] == "security" for i in f["inputs"])), None)
    if not form:
        print("[dvwa] security form not found")
        return False
    submit_form(client, form, {"security": level, "seclev_submit": "Submit"})
    client.security = get_dvwa_security(client)
    if client.security == level:
        print(f"[dvwa] security level set to {client.security}")
        return True
    print(f"[dvwa] failed to change security level (current: {client.security})")
    return False


def ensure_authenticated(client):
    if not client.username or not client.password:
        return
    check = client.get(client.start_url)
    if check is None:
        return
    if find_login_form(extract_forms(html_of(check), check.url)):
        attempt_login(client)


def crawl(client, start_url=None, max_pages=None):
    ensure_authenticated(client)
    start = normalize_url(start_url or client.start_url)
    max_pages = int(max_pages or cfg.get("max_crawl_pages", 40))
    queue = [start]
    seen = set()
    pages = []
    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        response = client.get(url)
        if response is None:
            continue
        ctype = content_type(response)
        body = html_of(response)
        if "html" not in ctype and "text" not in ctype and url != start:
            continue
        forms = extract_forms(body, url)
        page = {
            "url": url,
            "status": response.status_code,
            "headers": dict(response.headers),
            "text": body,
            "forms": forms,
            "links": [],
        }
        pages.append(page)
        if not BeautifulSoup:
            continue
        try:
            soup = BeautifulSoup(body, "html.parser")
        except Exception:
            continue
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"].strip()
            if not href or href.startswith(("#", "mailto:", "javascript:", "tel:", "data:")):
                continue
            absolute = client.absolute(href).split("#")[0]
            if not absolute or not client.in_scope(absolute):
                continue
            path = urllib.parse.urlsplit(absolute).path.lower()
            if re.search(r"\.(?:jpg|jpeg|png|gif|css|js|pdf|zip|ico|woff2?|svg|mp4|mp3)$", path):
                continue
            if "logout" in path:
                continue
            if absolute not in seen and absolute not in queue:
                page["links"].append(absolute)
                queue.append(absolute)
    print(f"[crawl] {len(pages)} page(s) inspected")
    return pages


def make_points(pages, max_points=None):
    max_points = int(max_points or cfg.get("max_injection_points", 40))
    skip_tokens = re.compile(r"token|csrf|nonce|authenticity|max_file_size|seclev", re.I)
    skip_fields = re.compile(r"btnclear|logout|reset|delete|remove|submit|upload$", re.I)
    points = []

    def add_query_points(url):
        parsed = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        for name, value in pairs:
            if skip_tokens.search(name):
                continue
            points.append({
                "kind": "query",
                "url": url,
                "param": name,
                "value": value,
                "method": "GET",
                "page_url": url,
            })

    for page in pages:
        add_query_points(page["url"])
        for form in page["forms"]:
            if any(i["type"] == "file" for i in form["inputs"]):
                continue
            page_lower = page["url"].lower()
            if "password_new" in page_lower or "csrf" in page_lower:
                continue
            for inp in form["inputs"]:
                if inp["type"] not in ("text", "password", "textarea", "search", "url", "email"):
                    continue
                if skip_tokens.search(inp["name"]) or skip_fields.search(inp["name"]):
                    continue
                points.append({
                    "kind": "form",
                    "url": form["page_url"],
                    "param": inp["name"],
                    "value": inp["value"],
                    "method": form["method"],
                    "page_url": form["page_url"],
                    "form": form,
                })
    unique = []
    seen = set()
    for point in points:
        key = (point["kind"], point["url"], point["param"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(point)
    return unique[:max_points]


def send_point(client, point, value):
    if point["kind"] == "query":
        parsed = urllib.parse.urlsplit(point["url"])
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        new_pairs = [(k, value if k == point["param"] else v) for k, v in pairs]
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(new_pairs), ""))
        return client.get(url)
    return submit_form(client, point["form"], {point["param"]: value}, fill_blank=True)


def original_value(point):
    value = point.get("value", "")
    return value if value != "" else "1"


def test_sqli(client, points, findings, deep=False):
    print("[sqli] testing parameters and forms")
    for point in points:
        base = send_point(client, point, original_value(point))
        if base is None:
            continue
        base_body = html_of(base)
        original = original_value(point)
        error_confirmed = False
        for payload in (original + "'", original + '"', original + "')", original + "'-- ", "'", '"', "1'"):
            response = send_point(client, point, payload)
            if response is None:
                continue
            body = html_of(response).lower()
            hit = next((p for p in SQL_ERROR_PATTERNS if p in body), None)
            if hit and hit not in base_body.lower():
                findings.add(
                    "high", "SQL injection (error based)",
                    point["url"], hit,
                    f"parameter/field '{point['param']}' produced a database error with payload {payload!r}",
                )
                error_confirmed = True
                break
        if error_confirmed:
            continue
        pairs = (
            (original + "' AND '1'='1", original + "' AND '1'='2"),
            (original + " AND 1=1", original + " AND 1=2"),
            (original + "' AND 1=1-- -", original + "' AND 1=2-- -"),
        )
        for true_payload, false_payload in pairs:
            r1 = send_point(client, point, true_payload)
            r2 = send_point(client, point, false_payload)
            if r1 is None or r2 is None:
                continue
            if r1.status_code != r2.status_code:
                continue
            if similarity(base_body, html_of(r1)) > 0.90 and similarity(html_of(r1), html_of(r2)) < 0.80:
                findings.add(
                    "high", "SQL injection (boolean based)",
                    point["url"], f"true/false payloads produce different results in '{point['param']}'",
                    "Response with a true condition matched the baseline while the false condition differed materially.",
                )
                break
        if deep:
            base_elapsed = base.elapsed.total_seconds() if base.elapsed else 0
            for payload in (
                original + "' AND SLEEP(2)-- -",
                original + "';SELECT SLEEP(2)-- -",
                "1' AND SLEEP(2)-- -",
                "1;SELECT SLEEP(2)-- -",
            ):
                started = time.monotonic()
                response = send_point(client, point, payload)
                elapsed = (time.monotonic() - started) if response is not None else 0
                if response is not None and elapsed - base_elapsed >= 1.6:
                    findings.add(
                        "high", "SQL injection (time based)",
                        point["url"], f"SLEEP payload delayed the response by {elapsed:.1f}s",
                        f"parameter/field '{point['param']}' appears to execute SQL time functions.",
                    )
                    break


def test_xss(client, points, findings):
    print("[xss] testing parameters and forms")
    stored_checked = set()
    for point in points:
        marker = "caiXSS" + rand_token(6)
        payload = f"<svg/onload=alert('{marker}')>"
        response = send_point(client, point, payload)
        if response is not None and payload in html_of(response):
            findings.add(
                "high", "Reflected cross-site scripting (XSS)",
                point["url"], payload,
                f"payload in '{point['param']}' was reflected without encoding",
            )
        if point["kind"] == "form" and response is not None and response.status_code < 500:
            page_url = point["page_url"]
            if page_url in stored_checked:
                continue
            stored_checked.add(page_url)
            time.sleep(0.15)
            page = client.get(page_url)
            if page is not None and payload in html_of(page):
                findings.add(
                    "high", "Stored cross-site scripting (XSS)",
                    page_url, payload,
                    "submitted payload persisted and was served back unencoded",
                )


def command_output_line(body, marker):
    for line in str(body).splitlines():
        text = re.sub(r"<[^>]+>", " ", line)
        text = html_module.unescape(text).strip()
        if text == marker:
            return True
    return False


def test_command_injection(client, points, findings):
    print("[cmd] testing command injection")
    for point in points:
        marker = "caiCMD" + rand_token(6)
        payloads = (
            f"127.0.0.1; echo {marker}",
            f"127.0.0.1 | echo {marker}",
            f"127.0.0.1 && echo {marker}",
            f"$(echo {marker})",
            f"`echo {marker}`",
            f"; echo {marker}",
        )
        for payload in payloads:
            response = send_point(client, point, payload)
            if response is None:
                continue
            body = html_of(response)
            if command_output_line(body, marker):
                findings.add(
                    "critical", "OS command injection",
                    point["url"], f"marker {marker} appeared in the response",
                    f"parameter/field '{point['param']}' was passed to a shell with payload {payload!r}",
                )
                break


def test_lfi(client, points, findings):
    print("[lfi] testing file inclusion")
    payloads = (
        "../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=../../index.php",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
    )
    for point in points:
        for payload in payloads:
            response = send_point(client, point, payload)
            if response is None:
                continue
            body = html_of(response)
            if "root:x:0:0" in body or "[extensions]" in body or "for 16-bit app support" in body:
                findings.add(
                    "high", "Local file inclusion / path traversal",
                    point["url"], f"payload {payload!r} revealed a local system file",
                    f"parameter/field '{point['param']}' is vulnerable.",
                )
                break
            if "PD9waHA" in body or "PD9waHA" in body.replace("\n", ""):
                findings.add(
                    "high", "Local file inclusion / PHP source disclosure",
                    point["url"], "php://filter payload returned PHP source",
                    f"parameter/field '{point['param']}' is vulnerable.",
                )
                break


def has_csrf_token(form):
    for inp in form["inputs"]:
        if re.search(r"token|csrf|nonce|authenticity|_wpnonce", inp["name"], re.I):
            return True
    return False


def test_csrf(client, pages, findings):
    print("[csrf] checking forms and session cookies")
    for page in pages:
        for form in page["forms"]:
            if form["method"] != "POST":
                continue
            if any(i["type"] == "password" for i in form["inputs"]) and not any(
                re.search(r"password_new|password_conf", i["name"], re.I) for i in form["inputs"]
            ):
                continue
            if not has_csrf_token(form):
                action = client.absolute(form["action"])
                findings.add(
                    "medium", "POST form lacks anti-CSRF token",
                    action, "form has no token/csrf/nonce field",
                    "Any cross-site page can submit this form if the victim has an active session.",
                )
    for name, meta in (client.auth_cookie_meta or client.cookie_meta).items():
        flags = []
        if not meta.get("secure"):
            flags.append("Secure")
        if not meta.get("httponly"):
            flags.append("HttpOnly")
        if meta.get("samesite") not in ("strict", "lax"):
            flags.append("SameSite")
        if flags:
            findings.add(
                "low", "Session cookie missing protective flags",
                client.origin, "missing: " + ", ".join(flags),
                f"cookie {name}",
            )


def test_weak_session_ids(client, findings):
    url = client.absolute("vulnerabilities/weak_id/")
    response = client.get(url)
    forms = extract_forms(html_of(response), url)
    form = next((f for f in forms if f["method"] == "POST"), None)
    if not form:
        return
    values = []
    for _ in range(3):
        response = submit_form(client, form)
        for name, value in client.cookies.items():
            if name.lower() in ("dvwassession", "dvwa_session"):
                values.append(value)
        time.sleep(0.05)
    if len(values) >= 2 and all(v.isdigit() for v in values):
        findings.add(
            "medium", "Predictable session identifiers",
            url, "generated values: " + ", ".join(values),
            "DVWA weak session ID generator produced numeric values.",
        )


def upload_candidates(client, page_url, filename, body):
    parsed = urllib.parse.urlsplit(page_url)
    base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rsplit("/", 1)[0] + "/", "", ""))
    candidates = [
        base + filename,
        base + "hackable/uploads/" + filename,
        base + "uploads/" + filename,
        client.origin + "/hackable/uploads/" + filename,
        client.origin + "/uploads/" + filename,
        client.origin + "/upload/" + filename,
    ]
    for match in re.findall(r"(?:href|src)=['\"]([^'\"]*" + re.escape(filename) + r"[^'\"]*)", body, re.I):
        candidates.append(client.absolute(match))
    seen = set()
    output = []
    for item in candidates:
        if item not in seen:
            seen.add(item)
            output.append(item)
    return output


def test_upload(client, pages, findings):
    if not cfg.get("allow_upload", True):
        return
    print("[upload] testing file upload forms")
    for page in pages:
        for form in page["forms"]:
            file_input = next((i for i in form["inputs"] if i["type"] == "file"), None)
            if not file_input:
                continue
            marker = "CAI_UPLOAD_" + rand_token(6)
            txt_name = "cai_probe_" + rand_token(6) + ".txt"
            php_name = "cai_probe_" + rand_token(6) + ".php"
            attempts = [
                (txt_name, marker, "text/plain", False),
                (php_name, "<?php echo '" + marker + "'; ?>", "image/jpeg", True),
            ]
            for filename, content, mime, executable in attempts:
                response = submit_form(client, form, files={file_input["name"]: (filename, content, mime)})
                if response is None:
                    continue
                body = html_of(response)
                uploaded = any(word in body.lower() for word in ("succes", "success", "uploaded", "upload complete"))
                for candidate in upload_candidates(client, form["page_url"], filename, body):
                    probe = client.get(candidate)
                    if probe is not None and marker in html_of(probe):
                        if executable:
                            findings.add(
                                "critical", "Unrestricted file upload with code execution",
                                candidate, f"uploaded {filename} and executed it",
                                "The upload form accepted an executable file and the uploaded content was served back.",
                            )
                            return
                        findings.add(
                            "medium", "File upload accepted",
                            candidate, f"uploaded {filename} and retrieved it",
                            "The upload handler accepted and served a file with an unrestricted extension.",
                        )
                        break
                if uploaded and not executable:
                    continue
def test_access_control(client, pages, findings):
    print("[access] checking unauthenticated access to protected pages")
    sensitive = re.compile(r"admin|setup|config|upload|exec|sqli|fi/|csrf|users|phpinfo|security", re.I)
    checked = 0
    for page in pages:
        url = page["url"]
        if not sensitive.search(url):
            continue
        checked += 1
        if checked > 12:
            break
        try:
            probe = requests.get(
                url,
                headers={"User-Agent": cfg.get("user_agent", "CAI-Pentest/2.0")},
                timeout=float(cfg.get("request_timeout", 10)),
                verify=False,
                allow_redirects=False,
            )
        except requests.RequestException:
            continue
        body = html_of(probe)
        if probe.status_code != 200 or find_login_form(extract_forms(body, url)):
            continue
        if similarity(page["text"], body) > 0.80 and len(body) > 200:
            findings.add(
                "high", "Missing authentication / access control",
                url, f"unauthenticated request returned HTTP {probe.status_code} with protected content",
                "The page was reachable without a session.",
            )


def header_audit(client, target=None, findings=None):
    findings = findings or Findings()
    url = normalize_url(target or client.start_url)
    response = client.get(url)
    if response is None:
        print(f"[headers] could not fetch {url}")
        return findings
    headers = {k.lower(): v for k, v in response.headers.items()}
    required = {
        "content-security-policy": "high",
        "x-content-type-options": "low",
        "x-frame-options": "medium",
        "referrer-policy": "low",
        "permissions-policy": "low",
    }
    if url.lower().startswith("https://"):
        required["strict-transport-security"] = "medium"
    for header, severity in required.items():
        if header not in headers:
            findings.add(severity, "Missing security header: " + header, url, "", "Response did not set the header.")
    if "server" in headers and headers["server"].strip():
        findings.add("info", "Server banner disclosed", url, headers["server"])
    if "x-powered-by" in headers:
        findings.add("info", "Technology disclosure", url, headers["x-powered-by"], "X-Powered-By header is present.")
    return findings


def directory_discovery(client, findings, limit=60):
    print("[dirs] running directory discovery")
    baseline_url = client.absolute("cai-missing-" + rand_token(10))
    baseline = client.get(baseline_url, allow_redirects=False)
    baseline_body = html_of(baseline)
    baseline_status = baseline.status_code if baseline is not None else 404
    wordlist = list(COMMON_PATHS)
    custom = cfg.get("wordlist")
    if custom:
        path = os.path.expanduser(str(custom))
        try:
            with open(path, "r", errors="ignore") as f:
                extra = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            wordlist.extend(extra[:2000])
            print(f"[dirs] loaded custom wordlist: {path}")
        except OSError as exc:
            print(f"[dirs] wordlist unavailable: {exc}")
    found = 0
    for entry in wordlist:
        if found >= limit:
            break
        entry = entry.lstrip("/")
        if re.search(r"logout|reset|delete|remove|clear|destroy", entry, re.I):
            continue
        url = client.absolute(entry)
        if not client.in_scope(url):
            continue
        response = client.get(url, allow_redirects=False)
        if response is None:
            continue
        status = response.status_code
        body = html_of(response)
        if status in (404, 410):
            continue
        if status == baseline_status and similarity(baseline_body, body) > 0.95:
            continue
        if status in (200, 401, 403, 301, 302):
            findings.add(
                "info", "Accessible path discovered", url, f"HTTP {status}",
                "Discovered during directory enumeration.",
            )
            found += 1
    if not found:
        print("[dirs] no additional paths found")


def assess(target, username=None, password=None, security=None, deep=True, findings=None, pages=None):
    findings = findings or Findings()
    client = WebClient(target, username=username, password=password)
    print(f"[web] target {client.start_url}")
    landing = client.get(client.start_url)
    if landing is None:
        print("[web] target is unreachable")
        return findings, client
    detect_dvwa(client, landing)
    if client.dvwa:
        print("[web] DVWA detected")
    if client.username and client.password:
        attempt_login(client)
    else:
        form = find_login_form(extract_forms(html_of(landing), client.start_url))
        if form:
            print("[web] login form detected (use --user and --password or 'username X password Y')")
    if security and client.dvwa:
        set_dvwa_security(client, security)
    if client.dvwa:
        current = get_dvwa_security(client)
        client.security = current
        if current:
            print(f"[web] DVWA security level: {current}")
        if current and current != "low" and cfg.get("active_tests", True):
            print(
                f"[dvwa] note: security level is '{current}', so vulnerable modules will "
                "not be exploitable. Pass security=low (or set it in DVWA) to enable active tests."
            )
            if sys.stdin.isatty():
                try:
                    answer = input("Set DVWA security level to low now? (y/N): ").strip().lower()
                except EOFError:
                    answer = "n"
                if answer in ("y", "yes"):
                    set_dvwa_security(client, "low")
    header_audit(client, client.start_url, findings)
    if cfg.get("active_tests", True):
        if deep:
            directory_discovery(client, findings)
            ensure_authenticated(client)
        pages = crawl(client)
        points = make_points(pages)
        print(f"[web] {len(points)} injection point(s)")
        test_sqli(client, points, findings, deep=deep)
        test_xss(client, points, findings)
        test_command_injection(client, points, findings)
        test_lfi(client, points, findings)
        test_upload(client, pages, findings)
        test_csrf(client, pages, findings)
        if client.authenticated:
            test_access_control(client, pages, findings)
            if client.dvwa:
                test_weak_session_ids(client, findings)
    else:
        print("[web] active tests disabled in config")
    return findings, client


def save_report(findings, target="", summary=""):
    os.makedirs(REPORT_DIR, exist_ok=True)
    path = os.path.join(REPORT_DIR, f"cai-report-{timestamp()}.md")
    lines = [
        "# CAI Assessment Report",
        "",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        f"- Target: {target}",
        f"- Findings: {len(findings.items)}",
        "",
    ]
    if summary:
        lines.extend(["## Summary", "", summary.strip(), ""])
    lines.extend(["## Findings", "", findings.render()])
    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"[report] saved to {path}")
    return path


def ai_summary(findings, target):
    if not findings.items:
        return "No vulnerabilities were confirmed during this assessment."
    prompt = (
        "You are a senior penetration tester. Write a concise evidence-based report for the "
        "findings below. Only use the supplied evidence; do not invent vulnerabilities. "
        "Group by severity, explain impact and give remediation.\n\n"
        f"Target: {target}\n\n" + findings.render()
    )
    result = ask_model(prompt)
    if ai_ok(result):
        print("\n--- AI Security Analysis ---")
        print(result)
        print("--- End ---\n")
        return result
    return ""


def parse_open_ports(out):
    ports = []
    for line in str(out or "").splitlines():
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 2 and parts[1].lower() == "open":
                ports.append(parts[0])
    return ports


def sanitize_target(target):
    target = str(target).strip()
    if not target or target.startswith("-") or any(ch in target for ch in ";&|`$()<>"):
        return None
    return target


def run_nmap(target):
    host = target
    port = None
    if re.match(r"^https?://", str(target), re.I):
        parsed = urllib.parse.urlsplit(str(target))
        host = parsed.hostname or ""
        port = parsed.port
    host = sanitize_target(host)
    if not host:
        return "nmap failed: invalid target"
    args = ["nmap"] + shlex.split(str(cfg.get("nmap_args", "-sS -Pn -T4"))) + [host]
    if port:
        args += ["-p", str(port)]
    if cfg.get("vuln_script"):
        args += ["--script", "vuln"]
    print("[nmap] " + " ".join(args))
    try:
        proc = subprocess.run(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=int(cfg.get("scan_timeout", 300)),
        )
        out = (proc.stdout or b"").decode("utf-8", "ignore")
        err = (proc.stderr or b"").decode("utf-8", "ignore")
        with open(LOG_FILE, "a") as f:
            f.write(f"\n---CMD---\n{' '.join(args)}\n---OUTPUT---\n{out}\n{err}\n---END---\n")
        if not out.strip() and err.strip():
            return "nmap failed: " + err.strip()
        return out
    except subprocess.TimeoutExpired:
        return "nmap failed: timed out"
    except Exception as e:
        return f"nmap failed: {e}"


def analyse_and_next_step(nmap_output, target=None):
    safe_output = str(nmap_output) if nmap_output is not None else ""
    prompt = (
        "You are a cyber-security analyst. Based only on the NMAP output below, give a "
        "prioritised pentest plan and next recommended steps.\n\n" + safe_output[:12000]
    )
    ai = ask_model(prompt)
    if not ai_ok(ai):
        ai = "AI analysis unavailable."
    print("\n--- AI Security Analysis ---")
    print(ai)
    print("--- End ---\n")
    next_prompt = (
        "Based on this scan output and analysis, output ONLY one safe next shell command to run, "
        "or the word none. Allowed tools: nmap, nikto, curl, gobuster, sqlmap, whatweb. "
        "Never target any host other than " + str(target or "the scan target") + ".\n\n" +
        str(nmap_output)[:8000]
    )
    next_cmd = ask_model(next_prompt)
    if not ai_ok(next_cmd):
        return
    next_cmd = next_cmd.strip().splitlines()[0].strip().strip("`")
    if next_cmd.lower().startswith("none") or not next_cmd:
        print("[No next step required]")
        return
    if not re.match(r"^(nmap|nikto|curl|gobuster|sqlmap|whatweb)\b", next_cmd):
        print("[ai] suggested command rejected: " + next_cmd)
        return
    print(f"\nAI recommends next step: {next_cmd}")
    if int(cfg.get("full_auto_next_step", 0)) == 1:
        run_and_log(next_cmd)
        return
    try:
        answer = input("Run this step? (y/N): ").strip().lower()
    except EOFError:
        answer = "n"
    if answer == "y":
        run_and_log(next_cmd)


def run_and_log(cmd):
    print("[run] " + cmd)
    try:
        proc = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        out = (proc.stdout or b"").decode("utf-8", "ignore")
        err = (proc.stderr or b"").decode("utf-8", "ignore")
        with open(LOG_FILE, "a") as f:
            f.write(f"\n---RUN---\n{cmd}\n{out}\n{err}\n")
        if out:
            print(out)
        if err:
            print(err)
    except Exception as e:
        print("Execution failed:", e)


def handle_scan_target(target, deep=True):
    print(f"Scanning {target}...")
    out = run_nmap(target)
    print("\n--- nmap output start ---")
    print(out)
    print("--- nmap output end ---\n")
    ports = parse_open_ports(out)
    if ports:
        print(f"Open ports: {ports}")
        web_ports = [p for p in ports if p.split("/")[0] in ("80", "443", "8080", "8081", "8000", "8443", "3000", "5000")]
        if web_ports:
            scheme = "https" if any(p.startswith("443") or p.startswith("8443") for p in web_ports) else "http"
            port = web_ports[0].split("/")[0]
            port_suffix = "" if (scheme == "http" and port == "80") or (scheme == "https" and port == "443") else ":" + port
            suggested = f"{scheme}://{target.split(':')[0]}{port_suffix}"
            print(f"[web] web service detected at {suggested}")
            if cfg.get("active_tests", True):
                try:
                    answer = input(f"Run web assessment against {suggested}? (Y/n): ").strip().lower()
                except EOFError:
                    answer = "n"
                if answer in ("", "y", "yes"):
                    findings, _ = assess(suggested, deep=deep)
                    ai_summary(findings, suggested)
                    save_report(findings, suggested)
    analyse_and_next_step(out, target)


def handle_scan_router():
    router = detect_router_ip()
    if not router:
        print("Unable to detect router IP")
        return
    handle_scan_target(router)


def detect_router_ip():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if parts[1] == "00000000":
                    gw = int(parts[2], 16)
                    return ".".join(str((gw >> 8 * i) & 255) for i in range(4))
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        parts[-1] = "1"
        return ".".join(parts)
    except Exception:
        return None


def run_nikto(target):
    if not shutil.which("nikto"):
        print("[nikto] not installed")
        return
    url = normalize_url(target)
    cmd = ["nikto", "-h", url, "-nointeractive", "-ask", "no"]
    print("[nikto] " + " ".join(cmd))
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        out = (proc.stdout or b"").decode("utf-8", "ignore")
        print(out)
        with open(LOG_FILE, "a") as f:
            f.write(f"\n---NIKTO---\n{url}\n{out}\n")
    except subprocess.TimeoutExpired:
        print("[nikto] timed out")
    except Exception as e:
        print("[nikto] failed:", e)


def run_sqlmap(target):
    if not shutil.which("sqlmap"):
        print("[sqlmap] not installed")
        return
    url = normalize_url(target)
    cmd = ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1", "--output-dir=logs/sqlmap"]
    print("[sqlmap] " + " ".join(cmd))
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900)
        out = (proc.stdout or b"").decode("utf-8", "ignore")
        print(out)
        with open(LOG_FILE, "a") as f:
            f.write(f"\n---SQLMAP---\n{url}\n{out}\n")
    except subprocess.TimeoutExpired:
        print("[sqlmap] timed out")
    except Exception as e:
        print("[sqlmap] failed:", e)


def tls_info(target):
    url = normalize_url(target)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        print("[tls] target is not HTTPS")
        return
    host = parsed.hostname
    port = parsed.port or 443
    context = ssl._create_unverified_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                print(f"[tls] protocol: {tls.version()}")
                print(f"[tls] cipher: {tls.cipher()[0]}")
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                print(f"[tls] subject: {subject}")
                print(f"[tls] issuer: {issuer}")
                print(f"[tls] expires: {cert.get('notAfter')}")
                expired = False
                try:
                    expires = ssl.cert_time_to_seconds(cert.get("notAfter", ""))
                    expired = expires < time.time()
                except Exception:
                    pass
                findings = Findings()
                if expired:
                    findings.add("high", "TLS certificate expired", url, cert.get("notAfter", ""))
                if tls.version() in ("TLSv1", "TLSv1.1"):
                    findings.add("medium", "Outdated TLS protocol", url, tls.version())
                save_report(findings, url)
    except Exception as e:
        print("[tls] failed:", e)


def whois_lookup(domain):
    if not shutil.which("whois"):
        print("[whois] not installed")
        return
    try:
        proc = subprocess.run(["whois", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        print((proc.stdout or b"").decode("utf-8", "ignore"))
    except Exception as e:
        print("[whois] failed:", e)


def dns_lookup(domain):
    try:
        host, aliases, addresses = socket.gethostbyname_ex(domain)
        print(f"[dns] host: {host}")
        if aliases:
            print(f"[dns] aliases: {', '.join(aliases)}")
        for addr in addresses:
            print(f"[dns] address: {addr}")
    except Exception as e:
        print("[dns] failed:", e)


def load_modules():
    loaded = {}
    if not os.path.isdir(MODULE_DIR):
        return loaded
    for path in glob.glob(f"{MODULE_DIR}/*.py"):
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if not hasattr(mod, "TAGS"):
                mod.TAGS = []
            loaded[name] = mod
        except Exception as e:
            print(f"[module] load error {name}: {e}")
    return loaded


def reload_modules():
    global modules
    modules = load_modules()
    print(f"[module] {len(modules)} module(s) loaded")


def module_ability(mod, cmd=None):
    fn = getattr(mod, "ability", None)
    if not fn:
        return None
    try:
        sig = inspect.signature(fn)
        if len(sig.parameters) >= 1:
            return fn(cmd)
        return fn()
    except TypeError:
        return fn()


def try_module(cmd, quiet=False):
    low = cmd.lower()
    for name, mod in modules.items():
        tags = [str(t).lower().replace("-", " ").replace("_", " ") for t in getattr(mod, "TAGS", [])]
        for tag in tags:
            if tag and (tag in low or low in tag):
                if not quiet:
                    print(f"[module] executing {name}")
                try:
                    result = module_ability(mod, cmd)
                    if result not in (None, ""):
                        print(result)
                    return True
                except Exception as e:
                    print(f"[module] {name} failed: {e}")
                    return True
    return False


def extend(cmd):
    prompt = (
        "Write a complete, runnable Python module for this pentest task:\n"
        f"{cmd}\n\n"
        "Rules:\n"
        "- Define TAGS as a list of natural language tags.\n"
        "- Define ability(cmd=None) that performs the action and prints real results.\n"
        "- Accept the target from cmd when supplied.\n"
        "- Use requests/subprocess/socket only, no pseudocode, no placeholders.\n"
        "- Return only valid Python code.\n"
    )
    raw = ask_model(prompt)
    if not ai_ok(raw):
        print("[extend] AI unavailable")
        return
    code = raw.replace("```python", "").replace("```", "")
    if "def ability" not in code:
        print("[extend] model did not return a valid module")
        return
    try:
        compile(code, "<generated>", "exec")
    except SyntaxError as e:
        print("[extend] generated code has a syntax error:", e)
        return
    os.makedirs(MODULE_DIR, exist_ok=True)
    path = os.path.join(MODULE_DIR, f"mod_{abs(hash(cmd)) % 10**8}.py")
    with open(path, "w") as f:
        f.write(code)
    print(f"[extend] module created: {path}")
    reload_modules()
    try_module(cmd)


def parse_file_target(text):
    urls = re.findall(r"https?://[^\s'\"<>]+", text, re.I)
    if urls:
        return urls[0].rstrip(").,;]`*").strip("`*")
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b", text)
    if ips:
        return ips[0]
    return None


def parse_mission(text):
    creds = extract_credentials(text)
    security = extract_security_level(text)
    target = parse_file_target(text)
    plan = []
    lowered = text.lower()
    if target and re.match(r"^https?://", target, re.I):
        plan.append("web assessment")
        if target:
            plan.append("authenticate if credentials allow")
    elif target:
        plan.append("network scan")
    if any(word in lowered for word in ("sql injection", "sqli", "xss", "command injection", "file inclusion", "file upload", "csrf")):
        plan.append("active vulnerability tests")
    if "auto attack" in lowered or "attack all" in lowered or "test each" in lowered:
        plan.append("all discovered DVWA-style sections")
    if not plan:
        plan.append("AI-assisted review of the loaded instructions")
    return {
        "target": target,
        "username": creds.get("username", ""),
        "password": creds.get("password", ""),
        "security": security,
        "plan": plan,
    }


def read_mission_file(path):
    path = os.path.expanduser(path.strip().strip("'\""))
    try:
        with open(path, "r", errors="replace") as f:
            text = f.read()
    except OSError as e:
        print(f"[read] {e}")
        return None
    if len(text) > 400000:
        print("[read] file is large; truncating to 400000 characters")
        text = text[:400000]
    print(f"\n--- {path} ---")
    print(text)
    print(f"--- end {path} ---\n")
    mission = parse_mission(text)
    mission["path"] = path
    mission["text"] = text
    print("[mission] target: " + str(mission["target"]))
    if mission["username"]:
        print("[mission] credentials: " + mission["username"] + " / ********")
    if mission["security"]:
        print("[mission] requested security level: " + mission["security"])
    print("[mission] plan: " + ", ".join(mission["plan"]))
    return mission


def execute_mission(mission, assume_yes=False):
    if not mission:
        print("[mission] no mission loaded")
        return
    target = mission.get("target")
    if not target:
        analysis = ask_model(
            "Review these pentest instructions and produce an actionable plan. "
            "Do not claim tests were run.\n\n" + mission.get("text", "")[:12000]
        )
        print(analysis if ai_ok(analysis) else "[mission] no target found in instructions")
        return
    if not assumption(assume_yes):
        return
    username = mission.get("username") or cfg.get("username")
    password = mission.get("password") or cfg.get("password")
    if re.match(r"^https?://", target, re.I):
        findings, _ = assess(
            target, username=username, password=password,
            security=mission.get("security"), deep=True,
        )
        summary = ai_summary(findings, target)
        save_report(findings, target, summary)
    else:
        handle_scan_target(target)


def assumption(assume_yes):
    if assume_yes:
        return True
    try:
        answer = input("Execute mission now? (y/N): ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def targeted_test(kind, target, username=None, password=None, security=None):
    client = WebClient(target, username=username, password=password)
    landing = client.get(client.start_url)
    if landing is None:
        print("[web] target unreachable")
        return Findings(), client
    detect_dvwa(client, landing)
    if client.username and client.password:
        attempt_login(client)
    if security and client.dvwa:
        set_dvwa_security(client, security)
    findings = Findings()
    header_audit(client, client.start_url, findings)
    pages = crawl(client)
    points = make_points(pages)
    print(f"[web] {len(points)} injection point(s)")
    if kind == "sqli":
        test_sqli(client, points, findings, deep=True)
    elif kind == "xss":
        test_xss(client, points, findings)
    elif kind in ("cmd", "rce"):
        test_command_injection(client, points, findings)
    elif kind in ("lfi", "fi"):
        test_lfi(client, points, findings)
    elif kind == "upload":
        test_upload(client, pages, findings)
    elif kind == "csrf":
        test_csrf(client, pages, findings)
    elif kind == "access":
        test_access_control(client, pages, findings)
    summary = ai_summary(findings, client.start_url)
    save_report(findings, client.start_url, summary)
    return findings, client


def brute_force(target, username=None, password=None, wordlist=None):
    client = WebClient(target, username="", password="")
    landing = client.get(client.start_url)
    if landing is None:
        print("[brute] target unreachable")
        return
    forms = extract_forms(html_of(landing), client.start_url)
    form = find_login_form(forms)
    if not form:
        print("[brute] no login form found")
        return
    user_field, pass_field = login_field_names(form)
    if not user_field or not pass_field:
        print("[brute] could not identify login fields")
        return
    users = [username] if username else list(DEFAULT_USERS)
    passwords = [password] if password else list(DEFAULT_PASSWORDS)
    if wordlist:
        path = os.path.expanduser(str(wordlist))
        try:
            with open(path, "r", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            if words:
                passwords = words
        except OSError as e:
            print(f"[brute] wordlist error: {e}")
    print(f"[brute] {len(users)} user(s) x {len(passwords)} password(s)")
    for user in users:
        for candidate in passwords:
            attempt = client.get(client.start_url)
            attempt_forms = extract_forms(html_of(attempt), client.start_url)
            current_form = find_login_form(attempt_forms) or form
            response = submit_form(client, current_form, {user_field: user, pass_field: candidate})
            if response is None:
                continue
            body = html_of(response)
            if "logout" in body.lower() or (
                urllib.parse.urlsplit(response.url).path != urllib.parse.urlsplit(form["page_url"]).path
                and "password" not in body.lower()
            ):
                print(f"[brute] VALID credentials: {user} / {candidate}")
                save_last(f"brute {target} --user {user} --pass {candidate}")
                return
            time.sleep(0.15)
    print("[brute] no valid credentials found")


def show_help():
    print(
        """
CAI commands
  help | ?                     show this help
  read <file>                  load a file as prompt / mission objectives
  run mission                  execute the loaded mission
  mission                      show the loaded mission plan
  scan <ip|url>                nmap scan (+ optional web assessment)
  scan my router               detect and scan the gateway
  web <url>                    full web assessment
  headers <url>                security header audit
  dirs <url>                   directory discovery
  sqli|xss|cmd|lfi|upload|csrf|access <url>
                               targeted real tests
  brute <url> [--user U] [--pass P] [--wordlist FILE]
  dvwa <url> [--user U] [--pass P] [security=low]
  nmap <target>                explicit nmap scan
  nikto|sqlmap <url>           run external scanner
  tls <https-url>              TLS certificate inspection
  dns <domain> | whois <domain>
  ai <question>                ask the configured model
  report                       show last findings and save a report
  model <name>                 switch model
  config                       show config
  set <key> <value>            update config
  extend <task>                generate a new module with AI (review before use)
  modules                      list loaded modules
  run <shell command>          execute a literal command
  exit | quit                  leave

Credentials can be supplied as --user/--pass, as
'username admin password secret', in config.json, or in CAI_USERNAME/CAI_PASSWORD.
"""
    )


def last_findings():
    global LAST_FINDINGS
    return LAST_FINDINGS


LAST_FINDINGS = Findings()
LAST_TARGET = ""
LAST_SUMMARY = ""
LAST_MISSION = None


def handle_command(cmd):
    global LAST_FINDINGS, LAST_TARGET, LAST_SUMMARY, LAST_MISSION, cfg
    cmd = str(cmd).strip()
    if not cmd:
        return
    save_last(cmd)
    low = cmd.lower()

    if low in ("exit", "quit", "q"):
        raise SystemExit
    if low in ("help", "?", "h"):
        show_help()
        return
    if low in ("config",):
        shown = dict(cfg)
        if shown.get("password"):
            shown["password"] = "********"
        print(json.dumps(shown, indent=4))
        return
    if low.startswith("set "):
        parts = shlex.split(cmd)
        if len(parts) < 3:
            print("usage: set <key> <value>")
            return
        key = parts[1]
        value = " ".join(parts[2:])
        cfg[key] = value
        save_config()
        print(f"[config] {key} updated")
        return
    if low.startswith("model ") or low.startswith("/model "):
        name = cmd.split(" ", 1)[1].strip()
        if ":" in name and name.startswith("ollama:"):
            name = name.split(":", 1)[1]
        cfg["default_model"] = name
        save_config()
        print(f"[model] default_model = {name}")
        return
    if low in ("modules", "/modules"):
        for name, mod in modules.items():
            print(f"{name}: {getattr(mod, 'TAGS', [])}")
        return
    if low.startswith("ai ") or low.startswith("ask "):
        question = cmd.split(" ", 1)[1]
        answer = ask_model(question)
        print(answer)
        return
    if low in ("report", "findings"):
        print(LAST_FINDINGS.render())
        if LAST_FINDINGS.items:
            save_report(LAST_FINDINGS, LAST_TARGET, LAST_SUMMARY)
        return
    if low.startswith("run "):
        command = cmd[4:].strip()
        print("[run] " + command)
        try:
            answer = input("Execute this shell command? (y/N): ").strip().lower()
        except EOFError:
            answer = "n"
        if answer in ("y", "yes"):
            run_and_log(command)
        return
    if low.startswith(("read ", "/read ", "load ", "/load ", "open ")):
        try:
            parts = shlex.split(cmd)
        except ValueError:
            parts = cmd.split()
        options = [p for p in parts[1:] if p.startswith("--")]
        files = [p for p in parts[1:] if not p.startswith("--")]
        path = files[0] if files else ""
        mission = read_mission_file(path)
        if mission:
            creds = extract_credentials(cmd)
            if creds.get("username"):
                mission["username"] = creds["username"]
            if creds.get("password"):
                mission["password"] = creds["password"]
            security = extract_security_level(cmd)
            if security:
                mission["security"] = security
            LAST_MISSION = mission
            if "--run" in options or "--yes" in options:
                execute_mission(mission, assume_yes="--yes" in options)
        return
    if low in ("mission", "/mission"):
        if LAST_MISSION:
            print("[mission] target: " + str(LAST_MISSION.get("target")))
            print("[mission] plan: " + ", ".join(LAST_MISSION.get("plan", [])))
        else:
            print("[mission] none loaded")
        return
    if low in ("run mission", "/mission run", "execute mission"):
        execute_mission(LAST_MISSION)
        return
    if low.startswith("extend ") or low.startswith("/extend "):
        extend(cmd.split(" ", 1)[1])
        return
    if low.startswith("dvwa"):
        rest = cmd[4:].strip()
        url = extract_url(rest)
        creds = extract_credentials(rest)
        security = extract_security_level(rest) or cfg.get("security_level") or None
        if not url:
            url = cfg.get("last_web_target") or extract_url(cmd) or "http://localhost:8081"
        LAST_FINDINGS, client = assess(
            url, username=creds.get("username"), password=creds.get("password"),
            security=security, deep=True,
        )
        LAST_TARGET = client.start_url
        LAST_SUMMARY = ai_summary(LAST_FINDINGS, LAST_TARGET)
        save_report(LAST_FINDINGS, LAST_TARGET, LAST_SUMMARY)
        cfg["last_web_target"] = LAST_TARGET
        save_config()
        return
    if low.startswith("brute"):
        rest = cmd[5:].strip()
        url = extract_url(rest)
        if not url:
            print("usage: brute <url> [--user U] [--pass P] [--wordlist FILE]")
            return
        creds = extract_credentials(rest)
        m = re.search(r"--wordlist\s+(\S+)", rest)
        brute_force(url, creds.get("username"), creds.get("password"), m.group(1) if m else None)
        return
    if low.startswith(("nikto ", "/nikto ")):
        run_nikto(extract_url(cmd) or cmd.split(" ", 1)[1])
        return
    if low.startswith(("sqlmap ", "/sqlmap ")):
        run_sqlmap(extract_url(cmd) or cmd.split(" ", 1)[1])
        return
    if low.startswith(("tls ", "ssl ")):
        tls_info(extract_url(cmd) or cmd.split(" ", 1)[1])
        return
    if low.startswith("dns "):
        dns_lookup(cmd.split(" ", 1)[1].strip())
        return
    if low.startswith("whois "):
        whois_lookup(cmd.split(" ", 1)[1].strip())
        return
    if low in ("scan my router", "/scan my router"):
        handle_scan_router()
        return
    if low.startswith(("nmap ", "/nmap ")):
        target = cmd.split(" ", 1)[1].strip()
        handle_scan_target(target)
        return
    if low.startswith("scan "):
        rest = cmd[5:].strip()
        target = extract_url(rest) or extract_ip(rest) or rest.split()[0]
        if re.match(r"^https?://", target, re.I):
            creds = extract_credentials(rest)
            security = extract_security_level(rest)
            LAST_FINDINGS, client = assess(target, creds.get("username"), creds.get("password"), security, deep=True)
            LAST_TARGET = client.start_url
            LAST_SUMMARY = ai_summary(LAST_FINDINGS, LAST_TARGET)
            save_report(LAST_FINDINGS, LAST_TARGET, LAST_SUMMARY)
        else:
            handle_scan_target(target)
        return
    tool_map = {
        "headers": "headers", "dirs": "dirs", "directory": "dirs",
        "sqli": "sqli", "xss": "xss", "cmd": "cmd", "rce": "cmd",
        "lfi": "lfi", "fi": "lfi", "upload": "upload", "csrf": "csrf",
        "access": "access", "web": "web", "attack": "web", "assess": "web",
        "pentest": "web",
    }
    first = low.split(" ", 1)[0].strip("/")
    if first in tool_map:
        rest = cmd.split(" ", 1)[1] if " " in cmd else ""
        url = extract_url(rest)
        creds = extract_credentials(rest)
        security = extract_security_level(rest)
        if not url:
            url = extract_ip(rest)
        if not url:
            url = cfg.get("last_web_target")
        if not url:
            print("usage: " + first + " <url>")
            return
        kind = tool_map[first]
        if kind == "headers":
            findings = Findings()
            client = WebClient(url, creds.get("username"), creds.get("password"))
            header_audit(client, url, findings)
            LAST_FINDINGS, LAST_TARGET = findings, url
            save_report(findings, url)
        elif kind == "dirs":
            findings = Findings()
            client = WebClient(url, creds.get("username"), creds.get("password"))
            landing = client.get(client.start_url)
            detect_dvwa(client, landing)
            if client.username and client.password:
                attempt_login(client)
            directory_discovery(client, findings)
            LAST_FINDINGS, LAST_TARGET = findings, url
            save_report(findings, url)
        elif kind == "web":
            LAST_FINDINGS, client = assess(
                url, creds.get("username"), creds.get("password"), security, deep=True,
            )
            LAST_TARGET = client.start_url
            LAST_SUMMARY = ai_summary(LAST_FINDINGS, LAST_TARGET)
            save_report(LAST_FINDINGS, LAST_TARGET, LAST_SUMMARY)
        else:
            LAST_FINDINGS = Findings()
            LAST_FINDINGS, client = targeted_test(
                kind, url, creds.get("username"), creds.get("password"), security,
            )
            LAST_TARGET = url
        cfg["last_web_target"] = url
        save_config()
        return
    url = extract_url(cmd)
    if url and not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    if url:
        creds = extract_credentials(cmd)
        security = extract_security_level(cmd)
        LAST_FINDINGS, client = assess(url, creds.get("username"), creds.get("password"), security, deep=True)
        LAST_TARGET = client.start_url
        LAST_SUMMARY = ai_summary(LAST_FINDINGS, LAST_TARGET)
        save_report(LAST_FINDINGS, LAST_TARGET, LAST_SUMMARY)
        cfg["last_web_target"] = LAST_TARGET
        save_config()
        return
    if try_module(cmd):
        return
    answer = ask_model(
        "You are CAI, a pentest assistant. The user asked something that did not match a built-in "
        "command. Give a concise, practical answer. Do not claim any test was run.\n\n" + cmd
    )
    print(answer)


def setup_readline():
    if not readline:
        return
    history = os.path.expanduser(str(cfg.get("history_file", ".cai_history")))
    if not os.path.isabs(history):
        history = os.path.join(os.path.dirname(os.path.abspath(__file__)), history)
    readline.set_history_length(1000)
    try:
        readline.read_history_file(history)
    except OSError:
        pass

    def save_history():
        try:
            readline.write_history_file(history)
        except OSError:
            pass

    atexit.register(save_history)


def repl():
    print("CAI Ollama By J~Net © 2025")
    print("Type 'help' for commands.")
    while True:
        try:
            cmd = input("cai> ").strip()
            if cmd:
                handle_command(cmd)
        except KeyboardInterrupt:
            print()
            continue
        except EOFError:
            print()
            break
        except SystemExit:
            break
        except Exception as e:
            print("Error:", e)


def run_cli(args):
    global cfg, AI_ENABLED, LAST_MISSION
    cfg = load_config()
    if args.model:
        cfg["default_model"] = args.model
        save_config()
    AI_ENABLED = not args.no_ai
    if args.timeout:
        cfg["request_timeout"] = args.timeout
    if args.wordlist:
        cfg["wordlist"] = args.wordlist
    if args.no_active:
        cfg["active_tests"] = False
    ensure_config()
    reload_modules()
    setup_readline()
    if args.file:
        mission = read_mission_file(args.file)
        LAST_MISSION = mission
        if mission:
            if args.user:
                mission["username"] = args.user
            if args.password:
                mission["password"] = args.password
            if args.security:
                mission["security"] = args.security
        if mission and args.yes:
            execute_mission(mission, assume_yes=True)
        return
    if args.command:
        for command in args.command:
            handle_command(command)
        return
    if args.url:
        creds = {}
        if args.user:
            creds["username"] = args.user
        if args.password:
            creds["password"] = args.password
        if args.security:
            creds["security"] = args.security
        LAST_FINDINGS, client = assess(args.url, creds.get("username"), creds.get("password"), creds.get("security"), deep=not args.quick)
        target = client.start_url
        summary = ai_summary(LAST_FINDINGS, target)
        save_report(LAST_FINDINGS, target, summary)
        return
    repl()


def main():
    parser = argparse.ArgumentParser(description="CAI pentest framework")
    parser.add_argument("-c", "--command", action="append", help="run a command and exit (repeatable)")
    parser.add_argument("-f", "--file", help="load a mission file")
    parser.add_argument("--url", help="assess a URL and exit")
    parser.add_argument("--user", help="username for authenticated testing")
    parser.add_argument("--password", help="password for authenticated testing")
    parser.add_argument("--security", help="DVWA security level")
    parser.add_argument("--wordlist", help="custom directory/brute-force wordlist")
    parser.add_argument("--timeout", type=float, help="HTTP request timeout")
    parser.add_argument("--model", help="set the default model")
    parser.add_argument("--quick", action="store_true", help="skip deep tests")
    parser.add_argument("--no-active", action="store_true", help="disable active tests")
    parser.add_argument("--no-ai", action="store_true", help="disable model calls")
    parser.add_argument("--yes", action="store_true", help="automatically execute loaded missions")
    args = parser.parse_args()
    run_cli(args)


if __name__ == "__main__":
    main()
