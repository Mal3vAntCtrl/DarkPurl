#!/usr/bin/env python3
"""
DARKPURL - a curl-native HTTP/s inspection tool for pentest/CTF lab work.

Core idea: curl is already the right tool for this - versatile, everywhere,
scriptable. This just removes the need to memorize/retype its syntax every
time, while keeping every request fully visible and fully in your control.
Nothing here picks values or fires requests without you choosing to.

Entry points (all converge on the same run_command -> response inspection
-> follow-up menu pipeline):
    - Quick look (0): one plain GET, for when you know nothing about the
      target yet. See the response, let it suggest what to check next.
    - Named recipes (1-6, 9): common request shapes (login, API, enum,
      custom-value test, session/cookie, raw) with only the relevant
      fields prompted for. Recipes you build get saved for reuse.
    - Crawl / enum (7, 8): pull links out of a page or probe a wordlist
      of common backend paths, building a persistent per-host sitemap.
    - Full builder (r): set method/headers/cookies/body by hand when you
      already know exactly what you want to send.

Every response gets scanned for basic fingerprinting signals (Server,
WWW-Authenticate, redirects, 5xx bodies, etc.) and, opt-in, offers
follow-ups (OPTIONS/HEAD/verbose re-run/carry a cookie forward) - never
automatic, always a menu you choose from.

Responses are also scanned for patterns that are WORTH MANUALLY TESTING
FURTHER - error strings, reflected input, structural hints. This is a
fingerprinting/triage layer only: it never crafts or sends payloads, never
decides anything is confirmed, and never runs an active test on its own.
It just names a category and points at what a human should go check by
hand, the same way Nikto/Wappalyzer-style tools flag "worth a look."

No external dependencies - stdlib only, so it runs anywhere curl does.
Recipes persist in ~/.curlmenu/recipes.json, sitemaps in
~/.curlmenu/sitemap_<host>.json, and every executed command is logged
to ~/.curlmenu/history.log.
"""

import datetime
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

STORE_DIR = Path.home() / ".curlmenu"
STORE_FILE = STORE_DIR / "recipes.json"
HISTORY_FILE = STORE_DIR / "history.log"
FINDINGS_FILE = STORE_DIR / "findings.json"
PROMPT_STR = "DARKPURL > "

STATE = {"target": "", "last_values": {}, "scheme": "http", "port": "", "last_command": "", "last_recipe": None, "last_raw": None, "last_pasted": "", "beginner_mode": True}

CATEGORIES = [
    ("0", "quicklook", "Quick look"),
    ("1", "login", "Login test"),
    ("2", "api", "API check"),
    ("3", "enum", "Check a path"),
    ("4", "injection", "Custom value test"),
    ("5", "session", "Session / cookie test"),
    ("6", "raw", "Saved custom requests"),
    ("7", "crawl", "Crawl mode"),
    ("8", "bruteenum", "Enum mode"),
    ("9", "paste", "Paste a curl command"),
    ("r", "builder", "Full request builder"),
]

BUILTIN_RECIPES = [
    {
        "name": "Basic form login (POST)",
        "category": "login",
        "template": "curl -s -i -X POST {scheme}://{target}{path} -d 'username={username}&password={password}'",
    },
    {
        "name": "Login, save cookie jar",
        "category": "login",
        "template": "curl -s -i -c cookies.txt -X POST {scheme}://{target}{path} -d 'username={username}&password={password}'",
    },
    {
        "name": "NTLM login",
        "category": "login",
        "template": "curl -s -i --ntlm -u '{domain}\\{username}:{password}' {scheme}://{target}{path}",
    },
    {
        "name": "Basic auth",
        "category": "login",
        "template": "curl -s -i -u '{username}:{password}' {scheme}://{target}{path}",
    },
    {
        "name": "GET with bearer token",
        "category": "api",
        "template": "curl -s -i -H 'Authorization: Bearer {token}' {scheme}://{target}{path}",
    },
    {
        "name": "POST JSON body",
        "category": "api",
        "template": "curl -s -i -X POST {scheme}://{target}{path} -H 'Content-Type: application/json' -d '{json_body}'",
    },
    {
        "name": "GET with custom header",
        "category": "api",
        "template": "curl -s -i -H '{header_name}: {header_value}' {scheme}://{target}{path}",
    },
    {
        "name": "Check endpoint status code only",
        "category": "enum",
        "template": "curl -s -o /dev/null -w '%{{http_code}}\\n' {scheme}://{target}{path}",
    },
    {
        "name": "Fetch path, show headers + body",
        "category": "enum",
        "template": "curl -s -i {scheme}://{target}{path}",
    },
    {
        "name": "Follow redirects, show final page",
        "category": "enum",
        "template": "curl -s -i -L {scheme}://{target}{path}",
    },
    {
        "name": "Ignore TLS cert (https lab targets)",
        "category": "enum",
        "template": "curl -s -i -k https://{target}{path}",
    },
    {
        "name": "Custom value in query param",
        "category": "injection",
        "template": "curl -s -i '{scheme}://{target}{path}?{param}={value}'",
    },
    {
        "name": "Custom value in POST body",
        "category": "injection",
        "template": "curl -s -i -X POST {scheme}://{target}{path} -d '{param}={value}'",
    },
    {
        "name": "Custom value in header",
        "category": "injection",
        "template": "curl -s -i {scheme}://{target}{path} -H '{header_name}: {value}'",
    },
    {
        "name": "Request with explicit cookie",
        "category": "session",
        "template": "curl -s -i -b '{cookie}' {scheme}://{target}{path}",
    },
    {
        "name": "Reuse saved cookie jar",
        "category": "session",
        "template": "curl -s -i -b cookies.txt {scheme}://{target}{path}",
    },
    {
        "name": "Forge/replace a session cookie value",
        "category": "session",
        "template": "curl -s -i -b '{cookie_name}={cookie_value}' {scheme}://{target}{path}",
    },
]

PLACEHOLDER_RE = re.compile(r"(?<!\{)\{(\w+)\}(?!\})")


def load_saved_recipes():
    if not STORE_FILE.exists():
        return []
    try:
        return json.loads(STORE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def save_recipes(recipes):
    STORE_DIR.mkdir(exist_ok=True)
    STORE_FILE.write_text(json.dumps(recipes, indent=2))


def placeholders_in(template):
    seen = []
    for name in PLACEHOLDER_RE.findall(template):
        if name not in ("target", "scheme") and name not in seen:
            seen.append(name)
    return seen


def ask(text):
    print(f"\n{text}\n")
    print("Your input below:")
    return input(PROMPT_STR).strip()


def prompt(text, default=None, example=None):
    hint = f" (e.g. {example})" if example else ""
    suffix = f" [{default}]" if default else ""
    val = ask(f"{text}{hint}{suffix}")
    return val if val else (default or "")


def yn_prompt(text, default=False):
    """Yes/no prompt where blank input keeps the given default instead of
    always meaning 'no' - lets a repeated flow stay silent when nothing
    needs to change."""
    suffix = " [Y/n]" if default else " [y/N]"
    val = ask(f"{text}{suffix}").lower()
    if not val:
        return default
    return val == "y"


def with_reuse(question, last_value, collect_fn, default=True):
    """
    The one 'reuse what I typed last time, or ask fresh' pattern used
    everywhere a piece of a request (method, headers, body, a pasted
    command...) might be identical to the last time this exact step ran.
    last_value is falsy -> always falls through to collect_fn(). Otherwise
    offers a single yes/no and either hands back last_value untouched or
    calls collect_fn() to gather it again.
    """
    if last_value and yn_prompt(question, default=default):
        return last_value
    return collect_fn()


def choose(options, title, allow_back=True):
    print(f"\n{title}")
    for key, label in options:
        print(f"  {key}) {label}")
    if allow_back:
        print("  b) back")
    print("  q) quit")
    print("\nYour input below:")
    choice = input(PROMPT_STR).strip().lower()
    if choice == "q":
        sys.exit(0)
    if choice == "b" and allow_back:
        return None
    valid = {k for k, _ in options}
    if choice not in valid:
        print("Not a valid option.")
        return choose(options, title, allow_back)
    return choice


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def category_menu():
    clear_screen()
    if STATE["last_command"]:
        print(f"Last command: {STATE['last_command']}")
        print("(press 'h' for full history)\n")
    opts = [("a", "Auto-scan (crawl + find issues fast)")]
    opts += [(k, label) for k, _, label in CATEGORIES]
    if STATE.get("last_recipe"):
        opts.insert(1, ("e", f"Repeat/edit last [{STATE['last_recipe']['name']}]"))
    opts.append(("c", "Compare mode"))
    opts.append(("m", "Sitemap"))
    opts.append(("f", "Findings log"))
    opts.append(("h", "History"))
    opts.append(("t", "Change target"))
    opts.append(("s", f"Scheme ({STATE['scheme']})"))
    opts.append(("p", f"Port ({STATE['port'] or 'default'})"))
    opts.append(("x", f"'What this means' notes on findings ({'on' if STATE.get('beginner_mode') else 'off'})"))
    opts.append(("?", "What do these mean?"))
    print(f"Target: {base_url()}")
    return choose(opts, "Menu:", allow_back=False)


def category_key_for(choice_num):
    for k, key, _ in CATEGORIES:
        if k == choice_num:
            return key
    return None


def recipe_menu(cat_key, all_recipes):
    matching = [r for r in all_recipes if r["category"] == cat_key]
    if not matching:
        if cat_key == "raw":
            print("Nothing saved here yet - build one with 'r' (full request builder) or save a")
            print("pasted command with '9', and it'll show up in this list from then on.")
        else:
            print("No recipes in this category yet.")
        return None
    opts = [(str(i + 1), r["name"]) for i, r in enumerate(matching)]
    choice = choose(opts, "Pick a recipe:")
    if choice is None:
        return None
    return matching[int(choice) - 1]


FIELD_EXAMPLES = {
    "path": "/login.php",
    "username": "admin",
    "password": "Summer2026!",
    "domain": "CORP",
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "json_body": '{"username":"admin","password":"admin"}',
    "header_name": "X-Forwarded-For",
    "header_value": "127.0.0.1",
    "param": "id",
    "value": "test123",
    "cookie": "PHPSESSID=abc123",
    "cookie_name": "PHPSESSID",
    "cookie_value": "deadbeef1234",
    "raw_args": "-v --max-time 5",
    "raw_command": "curl -s -i http://target/",
}


def fill_template(recipe):
    template = recipe["template"]
    fields = placeholders_in(template)
    values = {"target": target_with_port(), "scheme": STATE["scheme"]}
    for field in fields:
        default = STATE["last_values"].get(field, "")
        example = FIELD_EXAMPLES.get(field)
        values[field] = prompt(field, default=default, example=example)
        STATE["last_values"][field] = values[field]
    try:
        command = template.format(**values)
    except KeyError as e:
        print(f"\n⚠ Couldn't build the command: missing a value for {e}.")
        print("  This usually means the template references a field that wasn't filled in - try again.")
        return None
    except (ValueError, IndexError) as e:
        print(f"\n⚠ Couldn't build the command: the template has malformed {{braces}} ({e}).")
        print("  If you pasted this in, check for stray single '{' or '}' characters and escape")
        print("  literal braces as '{{' and '}}' (this matters for curl's -w format strings too).")
        return None
    return command, values


FLAG_GLOSSARY = {
    "-s": "silent - suppress the progress meter",
    "-i": "include response headers in the output",
    "-I": "HEAD request only - headers, no body",
    "-X": "explicit HTTP method",
    "-H": "custom header",
    "-d": "send data as the request body (POST, urlencoded by default)",
    "--data-binary": "send raw data exactly as-is, no re-encoding",
    "-b": "send these cookie(s) with the request",
    "-c": "write received cookies to this cookie-jar file",
    "-u": "username:password for HTTP auth",
    "-L": "follow redirects",
    "-k": "skip TLS certificate verification",
    "--ntlm": "authenticate using NTLM",
    "--negotiate": "authenticate using SPNEGO/Kerberos",
    "-o": "write response body to a file (/dev/null discards it)",
    "-w": "print this format string after the transfer completes",
    "-F": "multipart form field (file uploads, forms)",
    "-v": "verbose - show the full request and response, including headers",
    "--resolve": "manually map host:port to an IP, bypassing DNS",
    "-A": "set a custom User-Agent header",
    "-e": "set the Referer header",
    "-x": "route the request through a proxy",
    "-G": "turn -d fields into a query string on a GET",
    "--compressed": "request a compressed response and auto-decompress it",
}


def explain_command(command):
    try:
        tokens = shlex.split(command)
    except ValueError as e:
        print(f"⚠ Heads up: this command has unbalanced quotes ({e}) - curl may misparse it.")
        return
    lines = [f"  {tok:<16} {FLAG_GLOSSARY[tok]}" for tok in tokens if tok in FLAG_GLOSSARY]
    if lines:
        print("What this does:")
        for line in lines:
            print(line)


def log_history(command):
    STORE_DIR.mkdir(exist_ok=True)
    with open(HISTORY_FILE, "a") as f:
        f.write(f"{datetime.datetime.now().isoformat(timespec='seconds')}  {command}\n")


def show_history():
    if not HISTORY_FILE.exists():
        print("\nNo commands run yet.")
        return
    keyword = prompt("Filter history (blank = show last 30)", default="")
    lines = HISTORY_FILE.read_text().splitlines()
    if keyword:
        lines = [l for l in lines if keyword.lower() in l.lower()]
    for line in lines[-30:]:
        print(line)
    ask("\n(Enter to return to the menu)")


CURL_EXIT_CODES = {
    1: ("Unsupported protocol", "Check the scheme - did you mean http:// or https://? Try 's' at the top menu to toggle it."),
    2: ("curl failed to initialize", "Rare - try running the command again."),
    3: ("URL malformed", "Look for typos, stray spaces, or unescaped characters in the path."),
    5: ("Couldn't resolve proxy", "Check the proxy value you passed (e.g. via -x)."),
    6: ("Couldn't resolve host", "Check the target hostname/IP for typos - is it actually reachable from here?"),
    7: ("Failed to connect to host", "Host resolved but refused the connection - check the port and that the service is up."),
    9: ("Access denied by the server", "Check credentials, or whether this path needs auth you haven't supplied."),
    22: ("Server returned an HTTP error", "The endpoint returned 4xx/5xx - check the path, method, or payload."),
    26: ("Read error", "Local file read failed - check any file path you referenced (e.g. -F, --data-binary @file)."),
    28: ("Operation timed out", "Target may be slow, unreachable, or filtering you - check connectivity."),
    35: ("SSL/TLS handshake failed", "Try toggling scheme, or add -k via the tweak prompt to skip cert checks on lab targets."),
    47: ("Too many redirects", "Redirect loop - check the path, or drop -L if you added it."),
    51: ("SSL certificate verification failed", "Self-signed lab cert likely - add -k via the tweak prompt."),
    52: ("Empty reply from server", "Server closed the connection with no response - check the path/method."),
    55: ("Failed sending network data", "Connection dropped mid-request - check target/network stability."),
    56: ("Failure receiving network data", "Connection dropped mid-response - check target/network stability."),
    60: ("SSL certificate problem", "Add -k via the tweak prompt to skip verification on self-signed lab certs."),
    67: ("Login denied", "Check your username/password or auth flags."),
    127: ("curl not found", "curl doesn't seem to be installed or on your PATH."),
}


def diagnose_failure(command, result):
    code = result.returncode
    label, hint = CURL_EXIT_CODES.get(
        code, (f"curl exited with code {code}", "See curl's stderr below for the raw reason.")
    )
    print(f"\n⚠ Command failed: {label}")
    print(f"  Hint: {hint}")
    if result.stderr.strip():
        print(f"  curl says: {result.stderr.strip()}")
    print(f"  You ran:  {command}")
    print("  Pick the same recipe again to retry - your last values are pre-filled, just fix the field that's wrong.")


INTERESTING_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "via", "www-authenticate", "x-runtime", "x-drupal-cache",
]


def parse_response(text):
    lines = text.splitlines()
    status_code = None
    headers = {}
    body_start = len(lines)

    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
        i = 1
        while i < len(lines) and lines[i].strip():
            if ":" in lines[i]:
                k, v = lines[i].split(":", 1)
                headers[k.strip().lower()] = v.strip()
            i += 1
        body_start = i + 1

    body = "\n".join(lines[body_start:])
    return status_code, headers, body


def print_vuln_flag(line_no, snippet, tag, hint):
    """One consistent way to print a flagged finding, with an optional
    plain-language explanation underneath when beginner mode is on."""
    where = f"line {line_no}" if line_no else "header/context"
    print(f"  [{where}] {tag} - {hint}")
    print(f"      {snippet}")
    if STATE.get("beginner_mode"):
        explanation = explain_tag(tag)
        if explanation:
            print(f"      ↳ what this means: {explanation}")


def detect_signals(status_code, headers):
    """
    Header/status-level signals only. Anything about the BODY (error
    strings, stack traces, reflected values, etc.) is handled entirely by
    suggest_vulns() below, with a line number attached - keeping one
    flagging pipeline instead of two overlapping ones that'd repeat
    themselves in the output.
    """
    signals = []
    for h in INTERESTING_HEADERS:
        if h in headers:
            signals.append(f"{h}: {headers[h]}")
    if "set-cookie" in headers:
        signals.append(f"set-cookie: {headers['set-cookie']}")
    if "location" in headers:
        signals.append(f"location (redirect target): {headers['location']}")
    if status_code and status_code >= 500:
        signals.append(f"server error ({status_code}) - body flags below may explain why")
    if status_code in (401, 403):
        signals.append(f"access denied ({status_code}) - this path likely needs auth")
    return signals



# --- vulnerability-category suggester -----------------------------------
#
# Passive pattern matching only. This never crafts, mutates, or sends a
# payload, and it never claims a finding is confirmed - it points at the
# specific line that tripped a pattern, names a short vulnerability tag,
# and leaves everything else to the human. Think of it as a fingerprinting
# layer, same spirit as detect_signals() above, just line-level and much
# broader. Hints are kept to a few words on purpose - just enough to know
# what to go test, not a write-up.

# (regex, short tag, few-word hint) - checked one line of the body at a time,
# so a hit always has a concrete line number/snippet to point at.
VULN_LINE_PATTERNS = [
    # --- SQL injection (per-dialect error strings) ---
    (re.compile(r"sql syntax.*mysql|you have an error in your sql syntax", re.I), "SQLi (MySQL)", "MySQL syntax error leaked"),
    (re.compile(r"unclosed quotation mark after the character string|mssql|sqlsrv", re.I), "SQLi (MSSQL)", "MSSQL error string"),
    (re.compile(r"quoted string not properly terminated|ORA-\d{5}", re.I), "SQLi (Oracle)", "Oracle error string"),
    (re.compile(r"pg_query\(\)|postgresql.*error|invalid input syntax for", re.I), "SQLi (PostgreSQL)", "Postgres error string"),
    (re.compile(r"sqlite3?\.(OperationalError|Warning)|near \".*\": syntax error", re.I), "SQLi (SQLite)", "SQLite error string"),
    (re.compile(r"System\.Data\.SqlClient|Npgsql\.", re.I), "SQLi (.NET DB layer)", ".NET DB exception leaked"),
    (re.compile(r"org\.hibernate\.exception|could not execute query", re.I), "SQLi (Hibernate/JPA)", "ORM exception leaked"),

    # --- NoSQL / other query injection ---
    (re.compile(r"MongoError|E11000 duplicate key|BSONObj|\$where.*not allowed", re.I), "NoSQLi (MongoDB)", "Mongo error string"),
    (re.compile(r"com\.couchbase\.client|CouchbaseException", re.I), "NoSQLi (Couchbase)", "Couchbase error string"),
    (re.compile(r"redis\.exceptions|WRONGTYPE|ERR wrong number of arguments", re.I), "Possible Redis command injection", "Redis error string"),
    (re.compile(r"javax\.naming\.NamingException|LDAPException|invalid DN syntax", re.I), "LDAP injection", "LDAP error string"),
    (re.compile(r"XPathException|XPATH syntax error", re.I), "XPath injection", "XPath error string"),
    (re.compile(r"GraphQL error|Cannot query field|did you mean", re.I), "GraphQL error leak", "GraphQL resolver error"),
    (re.compile(r'"__schema"\s*:|"queryType"\s*:', re.I), "GraphQL introspection enabled", "schema introspection exposed"),

    # --- Server-side template injection (per engine) ---
    (re.compile(r"jinja2\.exceptions|TemplateSyntaxError", re.I), "SSTI (Jinja2)", "Jinja2 error leaked"),
    (re.compile(r"freemarker\.core|FreeMarker template error", re.I), "SSTI (FreeMarker)", "FreeMarker error leaked"),
    (re.compile(r"org\.thymeleaf|thymeleaf\.exceptions", re.I), "SSTI (Thymeleaf)", "Thymeleaf error leaked"),
    (re.compile(r"twig_error|Twig\\Error", re.I), "SSTI (Twig)", "Twig error leaked"),
    (re.compile(r"smarty[_.]?(compile|runtime)?error", re.I), "SSTI (Smarty)", "Smarty error leaked"),
    (re.compile(r"velocity\.exception|ParseErrorException", re.I), "SSTI (Velocity)", "Velocity error leaked"),
    (re.compile(r"HandlebarsException|Handlebars\.compile", re.I), "SSTI (Handlebars)", "Handlebars error leaked"),
    (re.compile(r"pug.*compile error|jade.*compile error", re.I), "SSTI (Pug/Jade)", "Pug/Jade error leaked"),
    (re.compile(r"ActionView::Template::Error|ERB::CompileError", re.I), "SSTI (ERB/Rails)", "ERB error leaked"),
    (re.compile(r"mustache\.js|Unclosed section", re.I), "SSTI (Mustache)", "Mustache error leaked"),

    # --- Command / OS injection ---
    (re.compile(r"sh: .*: command not found|/bin/sh: \d+:|/bin/bash: .*: command not found", re.I),
     "OS command injection", "shell error leaked"),
    (re.compile(r"is not recognized as an internal or external command", re.I),
     "OS command injection (Windows)", "cmd.exe error leaked"),
    (re.compile(r"sh: syntax error|unexpected EOF while looking for matching", re.I),
     "OS command injection", "shell syntax error leaked"),

    # --- Path traversal / LFI / RFI ---
    (re.compile(r"root:.*:0:0:", re.I), "LFI / path traversal", "looks like /etc/passwd content"),
    (re.compile(r"\[boot loader\]|\[fonts\]\s*$", re.I), "LFI / path traversal", "looks like Windows boot.ini/win.ini content"),
    (re.compile(r"failed to open stream|include\(\).*failed to open|require\(\).*failed to open", re.I),
     "LFI (PHP include/require)", "PHP file-open failure leaked"),
    (re.compile(r"allow_url_include|allow_url_fopen", re.I), "Possible RFI (PHP)", "remote-include config referenced"),

    # --- XXE ---
    (re.compile(r"org\.xml\.sax\.SAXParseException|DOCTYPE is disallowed|external entity|SYSTEM \".*\"", re.I),
     "XXE (XML external entity)", "XML parser/entity error leaked"),
    (re.compile(r"lxml\.etree\.XMLSyntaxError|xml\.parsers\.expat\.ExpatError", re.I),
     "XXE (XML external entity)", "Python XML parser error leaked"),

    # --- Insecure deserialization ---
    (re.compile(r"java\.io\.(InvalidClassException|StreamCorruptedException|OptionalDataException)|readObject", re.I),
     "Insecure deserialization (Java)", "Java deserialize error leaked"),
    (re.compile(r"unserialize\(\).*Error|__PHP_Incomplete_Class", re.I),
     "Insecure deserialization (PHP)", "PHP unserialize() error leaked"),
    (re.compile(r"pickle\.UnpicklingError|_pickle\.UnpicklingError", re.I),
     "Insecure deserialization (Python pickle)", "pickle error leaked"),
    (re.compile(r"System\.Runtime\.Serialization|BinaryFormatter\.Deserialize|TypeNameHandling", re.I),
     "Insecure deserialization (.NET)", ".NET deserialize reference leaked"),
    (re.compile(r"com\.fasterxml\.jackson.*PolymorphicTypeValidator|@class\"\s*:", re.I),
     "Insecure deserialization (Jackson polymorphic)", "Jackson polymorphic type hint leaked"),

    # --- SSRF hints ---
    (re.compile(r"169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data", re.I),
     "Possible SSRF (cloud metadata reachable)", "cloud metadata endpoint referenced"),

    # --- Auth / JWT / crypto hints ---
    (re.compile(r'"alg"\s*:\s*"none"', re.I), "JWT 'alg:none' accepted", "unsigned JWT alg referenced"),
    (re.compile(r"jwt\.exceptions\.|InvalidSignatureError|InvalidAlgorithmError", re.I),
     "JWT validation error leaked", "JWT library error leaked"),

    # --- Framework / CMS debug pages ---
    (re.compile(r"django\.core\.exceptions|DisallowedHost|DEBUG = True|Django Version:", re.I),
     "Framework debug exposed (Django)", "Django debug page"),
    (re.compile(r"werkzeug|flask\.debughelpers|Werkzeug Debugger", re.I),
     "Framework debug exposed (Flask)", "Werkzeug debug output"),
    (re.compile(r"whoops|laravel.*exception|Illuminate\\", re.I),
     "Framework debug exposed (Laravel)", "Whoops/Laravel error page"),
    (re.compile(r"Whitelabel Error Page|org\.springframework\.", re.I),
     "Framework debug exposed (Spring Boot)", "Spring stack trace/whitelabel page"),
    (re.compile(r"System\.Web\.HttpException|Server Error in '/' Application", re.I),
     "Framework debug exposed (ASP.NET)", "ASP.NET yellow screen of death"),
    (re.compile(r"at Object\.<anonymous>|Error: Cannot GET|node_modules[\\/]", re.I),
     "Framework debug exposed (Node/Express)", "Node stack trace leaked"),
    (re.compile(r"ActionController::RoutingError|Rails\.root|ActiveRecord::", re.I),
     "Framework debug exposed (Rails)", "Rails error page"),
    (re.compile(r"phpinfo\(\)|PHP Version =>", re.I),
     "phpinfo() exposed", "full PHP config disclosure"),

    # --- CMS fingerprints worth checking against known CVEs ---
    (re.compile(r"wp-content/plugins/|wp-json/|/wp-includes/", re.I),
     "WordPress detected", "check plugin/core versions for CVEs"),
    (re.compile(r"Drupal\.settings|/sites/default/files/|X-Generator: Drupal", re.I),
     "Drupal detected", "check core/module versions for CVEs"),
    (re.compile(r"/components/com_|Joomla!", re.I),
     "Joomla detected", "check component versions for CVEs"),
    (re.compile(r"Magento_|/skin/frontend/", re.I),
     "Magento detected", "check version for known CVEs"),

    # --- Generic stack traces / verbose errors / info disclosure ---
    (re.compile(r"traceback \(most recent call last\)", re.I), "Stack trace leaked (Python)", "full traceback in body"),
    (re.compile(r"stack trace", re.I), "Stack trace leaked", "stack trace string present"),
    (re.compile(r"fatal error", re.I), "Verbose error output", "fatal error string leaked"),
    (re.compile(r"^warning: ", re.I), "Verbose error output", "raw warning/notice leaked"),
    (re.compile(r"internal server error", re.I), "Verbose error output", "raw 5xx error page returned"),
    (re.compile(r"index of /", re.I), "Directory listing exposed", "autoindex is on"),
    (re.compile(r"\.git/HEAD|ref: refs/heads/", re.I), "Exposed .git", "git internals reachable"),
    (re.compile(r"DB_PASSWORD|DB_USERNAME=|APP_KEY=|AWS_SECRET_ACCESS_KEY", re.I), "Exposed secrets/.env", "credential-like var leaked"),
]

# Plain-language, one-or-two-sentence explanations for someone new to this.
# Keyed by "family" - the part of the tag before any "(Engine)" suffix - so
# every per-database/per-template-engine variant shares one explanation
# instead of needing 30 near-duplicate blurbs. Looked up in explain_tag().
BEGINNER_EXPLAINERS = {
    "SQLi": "The app's error message looks like it came straight from a database query. "
            "That can mean your input is being pasted into a SQL query without being cleaned up first - "
            "which is what SQL Injection attacks target.",
    "NoSQLi": "Same idea as SQL Injection, but for a NoSQL database like MongoDB - "
              "an error like this suggests input might reach the database query directly.",
    "LDAP injection": "This error suggests input might be reaching a directory-service (LDAP) query unfiltered - "
                       "similar risk to SQL injection, just for a different kind of database.",
    "XPath injection": "This error suggests input might be reaching an XML query unfiltered - "
                        "worth checking if you can manipulate what data it returns.",
    "GraphQL": "GraphQL APIs describe their whole data model in one place. If introspection is on, "
               "or errors leak resolver details, it's easier to map out what data exists.",
    "SSTI": "Server-Side Template Injection. The app might be running a page-template engine on your input "
            "directly, which in the worst case can let you execute code on the server.",
    "OS command injection": "This looks like a shell/command-line error. If input is reaching a system command, "
                             "that's one of the most serious bug classes there is - it can mean full server control.",
    "LFI": "Local File Inclusion. The app might let a filename parameter pull in files from elsewhere on the "
           "server that you're not supposed to see (like /etc/passwd or config files).",
    "RFI": "Remote File Inclusion. The app's file-include setting might let it load and run a file from a "
           "URL you control - a step up in severity from LFI.",
    "XXE": "XML External Entity. If the app parses XML you send it, a crafted entity might let you read local "
           "files or make the server send requests on your behalf.",
    "Insecure deserialization": "The app appears to convert incoming data back into objects/data structures. "
                                 "If that data isn't trusted, this pattern is a classic way to run code on the server.",
    "Possible SSRF": "Server-Side Request Forgery. Something in the response suggests the server might make "
                      "requests to internal addresses (like cloud metadata) on your behalf.",
    "JWT": "JSON Web Tokens carry login/session info. If the server accepts a token with no signature, or leaks "
           "verification errors, its auth might be easier to forge than it should be.",
    "Framework debug exposed": "Debug mode looks like it's turned on. Debug pages often leak source code, "
                                "config values, and full stack traces that should never be public.",
    "phpinfo() exposed": "A phpinfo() page dumps the entire PHP configuration - versions, paths, sometimes "
                          "even credentials. It should never be reachable on a live site.",
    "WordPress detected": "WordPress often has known vulnerabilities in outdated plugins/themes - "
                           "worth checking the exact versions in use against public advisories.",
    "Drupal detected": "Same idea as WordPress - check the Drupal core/module versions against known CVEs.",
    "Joomla detected": "Same idea as WordPress - check the Joomla component versions against known CVEs.",
    "Magento detected": "Same idea as WordPress - check the Magento version against known CVEs.",
    "Stack trace leaked": "A full error trace is showing. Besides being embarrassing for the developers, "
                           "it often reveals file paths, library versions, and logic worth knowing about.",
    "Verbose error output": "The app is showing a raw, developer-facing error instead of a clean error page - "
                             "worth reading in full for anything sensitive.",
    "Directory listing exposed": "The web server is showing a raw file listing instead of a normal page - "
                                  "you can literally browse what files exist in that folder.",
    "Exposed .git": "The .git folder is reachable, which can mean the entire source code history - "
                     "including anything ever committed, like old passwords - can be downloaded.",
    "Exposed secrets/.env": "Something that looks like a real credential or secret key showed up in the "
                             "response. Treat this as sensitive - don't paste it anywhere public.",
    "Reflected input": "The value you typed came back unchanged in the page. This is the first ingredient "
                        "for Cross-Site Scripting (XSS) - worth checking if it's properly escaped.",
    "Possible IDOR": "Insecure Direct Object Reference. The request uses a plain ID (like a number) to pick "
                      "a record. Try changing it slightly and see if you get someone else's data back.",
    "Cookie hardening gap": "A session cookie is missing a security flag (HttpOnly/Secure/SameSite). "
                             "These flags reduce the damage an attacker can do even if they find another bug.",
    "Possible open redirect": "The server's redirect target looks like it includes something you typed. "
                               "If so, this URL could be reused to send people somewhere malicious while "
                               "looking like it comes from the real site.",
    "CORS misconfiguration": "The CORS policy allows any website to make authenticated requests here - "
                              "that's usually a real bug, not just permissive by design.",
    "Permissive CORS": "The CORS policy allows any website to read this response. Fine for public data, "
                        "worth double-checking there's nothing sensitive in it.",
}


def explain_tag(tag):
    """Look up a plain-language explanation for a vuln tag. Tags like
    'SQLi (MySQL)' fall back to the family before the parenthesis
    ('SQLi'), and any tag containing a known key (like 'Possible RFI
    (PHP)' containing 'RFI') falls back to a substring match, so one
    explainer covers every variant of a tag."""
    if tag in BEGINNER_EXPLAINERS:
        return BEGINNER_EXPLAINERS[tag]
    family = tag.split(" (")[0]
    if family in BEGINNER_EXPLAINERS:
        return BEGINNER_EXPLAINERS[family]
    # Longest-key-first so a specific key (e.g. "Framework debug exposed")
    # wins over a shorter one that might also appear as a substring.
    for key in sorted(BEGINNER_EXPLAINERS, key=len, reverse=True):
        if key in tag:
            return BEGINNER_EXPLAINERS[key]
    return None


def suggest_vulns(status_code, headers, body, request_values=None):
    """
    Return a list of (line_no, line_snippet, tag, hint) tuples pointing at
    the exact line that tripped a pattern, plus a couple of structural
    (header/context) checks that don't map to a single body line - those
    use line_no=None. Advisory only: names what to go check, never a
    payload, never a confirmation.
    """
    found = []
    body_text = body or ""
    lines = body_text.splitlines()

    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        for pattern, tag, hint in VULN_LINE_PATTERNS:
            if pattern.search(line):
                snippet = line.strip()
                if len(snippet) > 100:
                    snippet = snippet[:97] + "..."
                found.append((line_no, snippet, tag, hint))

    # Reflected input - precondition for XSS/SSTI, no single "line" to
    # blame beyond wherever it shows up, so report the first occurrence.
    if request_values:
        for field, val in request_values.items():
            if field in ("target", "scheme", "path"):
                continue
            if isinstance(val, str) and len(val) >= 3 and val in body_text:
                idx = body_text.find(val)
                line_no = body_text.count("\n", 0, idx) + 1
                snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else val
                if len(snippet) > 100:
                    snippet = snippet[:97] + "..."
                found.append((line_no, snippet, "Reflected input", f"your '{field}' value came back verbatim"))

    # --- header/context checks: not tied to a body line ---
    path = (request_values or {}).get("path", "") or ""
    if re.search(r"/\d+(/|$)", path) or re.search(r"[?&](id|user_id|uid|acct|account)=\d+", path, re.I):
        found.append((None, path, "Possible IDOR", "numeric ID in path/query"))

    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        lower = set_cookie.lower()
        missing = [f for f, present in (("HttpOnly", "httponly" in lower),
                                         ("SameSite", "samesite" in lower)) if not present]
        if STATE["scheme"] == "https" and "secure" not in lower:
            missing.append("Secure")
        if missing:
            found.append((None, set_cookie[:100], "Cookie hardening gap", f"missing {', '.join(missing)}"))

    location = headers.get("location", "")
    if location and request_values:
        for field, val in request_values.items():
            if field in ("target", "scheme", "path"):
                continue
            if isinstance(val, str) and val and val in location:
                found.append((None, location[:100], "Possible open redirect", f"Location reflects '{field}'"))
                break

    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        found.append((None, "Access-Control-Allow-Origin: * + credentials: true", "CORS misconfiguration", "wildcard origin + credentials"))
    elif acao == "*":
        found.append((None, "Access-Control-Allow-Origin: *", "Permissive CORS", "wildcard origin"))

    # De-duplicate while preserving order.
    seen = set()
    deduped = []
    for item in found:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def load_findings():
    if not FINDINGS_FILE.exists():
        return []
    try:
        return json.loads(FINDINGS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def save_finding(line_no, snippet, tag, hint, command):
    STORE_DIR.mkdir(exist_ok=True)
    findings = load_findings()
    findings.append({
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "target": target_with_port(),
        "line": line_no,
        "snippet": snippet,
        "tag": tag,
        "hint": hint,
        "command": command,
        "confirmed": False,
    })
    FINDINGS_FILE.write_text(json.dumps(findings, indent=2))


def show_findings():
    findings = [f for f in load_findings() if f["target"] == target_with_port()]
    if not findings:
        print(f"\nNo findings logged yet for {target_with_port()}.")
        return
    print(f"\nFindings for {target_with_port()} ({len(findings)}):")
    for i, f in enumerate(findings, 1):
        mark = "✔ confirmed" if f.get("confirmed") else "unconfirmed"
        where = f"line {f['line']}" if f.get("line") else "header/context"
        print(f"  {i}) [{mark}] {f['tag']}  ({where}) - {f['hint']}")
        print(f"      {f['snippet']}")
        print(f"      from: {f['command']}")
        if STATE.get("beginner_mode"):
            explanation = explain_tag(f["tag"])
            if explanation:
                print(f"      ↳ what this means: {explanation}")
    ans = prompt("\nMark one as confirmed/tested? (number, blank to skip)", default="")
    if ans:
        try:
            idx = int(ans) - 1
            all_findings = load_findings()
            # map back to the global list index
            target_findings_indices = [i for i, f in enumerate(all_findings) if f["target"] == target_with_port()]
            global_idx = target_findings_indices[idx]
            all_findings[global_idx]["confirmed"] = True
            FINDINGS_FILE.write_text(json.dumps(all_findings, indent=2))
            print("Marked as confirmed.")
        except (ValueError, IndexError):
            print("Not a valid choice.")


def offer_inspection_menu(status_code, headers):
    ans = ask("\nWant a menu of inspection follow-ups based on this response? [y/N]").lower()
    if ans != "y":
        return
    inspection_loop(status_code, headers)


def inspection_loop(status_code, headers):
    current_path = STATE["last_values"].get("path", "/")

    options = []
    if headers.get("location"):
        options.append(("1", f"Follow the redirect - set path to {headers['location']}"))
    if headers.get("set-cookie"):
        options.append(("2", "Carry this Set-Cookie into the cookie field for your next request"))
    options.append(("3", f"Try OPTIONS on {current_path} (see which HTTP methods are allowed)"))
    options.append(("4", f"Try HEAD on {current_path} (headers only, no body)"))
    options.append(("5", "Re-run the last request with -v (full request/response detail)"))

    choice = choose(options, "Inspect further:")
    if choice is None:
        return

    if choice == "1":
        location = headers["location"]
        parsed = urllib.parse.urlparse(location)
        if parsed.netloc and STATE["target"] not in parsed.netloc:
            switch = ask(f"That redirects to a different host ({parsed.netloc}) - switch target? [y/N]").lower()
            if switch != "y":
                print("Keeping current target - redirect not followed.")
                return
            STATE["target"] = parsed.hostname or parsed.netloc
            STATE["port"] = str(parsed.port) if parsed.port else ""
            if parsed.scheme:
                STATE["scheme"] = parsed.scheme
        new_path = parsed.path or "/"
        STATE["last_values"]["path"] = new_path
        print(f"Path set to {new_path} - pick a recipe to send the next request.")
    elif choice == "2":
        cookie_kv = headers["set-cookie"].split(";", 1)[0]
        STATE["last_values"]["cookie"] = cookie_kv
        print(f"Saved '{cookie_kv}' - it'll be the default next time a recipe asks for a cookie.")
    elif choice in ("3", "4", "5"):
        commands = {
            "3": f"curl -s -i -X OPTIONS {base_url()}{current_path}",
            "4": f"curl -s -I {base_url()}{current_path}",
            "5": f"curl -s -i -v {base_url()}{current_path}",
        }
        new_status, new_headers = execute_and_report(commands[choice])

        next_step = choose(
            [("1", "Keep testing this response"), ("2", "Return to main menu")],
            "\nWhat next?",
            allow_back=False,
        )
        if next_step == "1" and new_status is not None:
            inspection_loop(new_status, new_headers)


def execute_and_report(command, request_values=None):
    """
    Actually run a command and show what came back. Returns (status_code,
    headers) so the caller can decide what's next. request_values, when
    available, is passed through to the vuln-suggester purely to reason
    about reflection/structure of the request that was actually sent.
    """
    print(f"\n$ {command}\n")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
    except OSError as e:
        print(f"\n⚠ Couldn't run the command at all: {e}")
        print("  Check that curl is installed and the command has no shell-breaking syntax.")
        return None, {}

    status_code, headers, body = None, {}, ""
    if result.stdout:
        status_code, headers, body = parse_response(result.stdout)
        first_line = result.stdout.splitlines()[0] if result.stdout.splitlines() else ""
        if first_line.startswith("HTTP/"):
            print(f"« {first_line} »\n")
        print(result.stdout)

    if result.returncode != 0:
        print()
        diagnose_failure(command, result)
    elif result.stderr.strip():
        print("\n--- stderr ---")
        print(result.stderr)

    signals = detect_signals(status_code, headers) if result.stdout else []
    if signals:
        print("\nSignals worth noting:")
        for s in signals:
            print(f"  - {s}")

    if result.stdout:
        vulns = suggest_vulns(status_code, headers, body, request_values)
        if vulns:
            print("\n⚑ Worth a look (unconfirmed - verify manually):")
            for line_no, snippet, tag, hint in vulns:
                print_vuln_flag(line_no, snippet, tag, hint)
                save_finding(line_no, snippet, tag, hint, command)
            print(f"\n  Logged to {FINDINGS_FILE} - view anytime with 'f' at the main menu.")

    log_history(command)
    STATE["last_command"] = command
    return status_code, headers


# --- compare / diff mode -------------------------------------------------
#
# Send the same request shape multiple times with one field varied across
# values YOU type in, then show what actually changed between responses -
# status, size, timing, and a body diff. This is the same technique as
# manually running curl a few times and eyeballing the differences; it just
# does the running and diffing for you. It never picks or generates the
# values being tested (no built-in payload lists) and never claims a
# difference proves anything - a size/status/body change is a signal to go
# confirm by hand, same posture as the rest of the tool.

COMPARE_MARKER_STATUS = "___DARKPURL_STATUS___"
COMPARE_MARKER_SIZE = "___DARKPURL_SIZE___"
COMPARE_MARKER_TIME = "___DARKPURL_TIME___"


def run_compare_command(command):
    """
    Run one curl command with -w markers appended so status/size/timing can
    be parsed out even though -i is also in use. Returns a dict with
    status_code, size, time, headers, body, raw_returncode - or None on a
    hard failure to run curl at all.
    """
    wfmt = (
        f"\\n{COMPARE_MARKER_STATUS}:%{{http_code}}"
        f"\\n{COMPARE_MARKER_SIZE}:%{{size_download}}"
        f"\\n{COMPARE_MARKER_TIME}:%{{time_total}}\\n"
    )
    full_command = f"{command} -w '{wfmt}'"
    try:
        result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
    except OSError as e:
        print(f"\n⚠ Couldn't run the command at all: {e}")
        return None

    stdout = result.stdout
    status, size, time_total = None, None, None
    m = re.search(rf"{COMPARE_MARKER_STATUS}:(\d+)", stdout)
    if m:
        status = int(m.group(1))
    m = re.search(rf"{COMPARE_MARKER_SIZE}:(\d+)", stdout)
    if m:
        size = int(m.group(1))
    m = re.search(rf"{COMPARE_MARKER_TIME}:([\d.]+)", stdout)
    if m:
        time_total = float(m.group(1))

    # Strip the marker block back out before parsing headers/body normally.
    clean_stdout = re.split(rf"\n{COMPARE_MARKER_STATUS}:", stdout)[0]
    _, headers, body = parse_response(clean_stdout)

    return {
        "command": full_command,
        "status": status,
        "size": size,
        "time": time_total,
        "headers": headers,
        "body": body,
        "returncode": result.returncode,
        "stderr": result.stderr,
    }


def diff_bodies(baseline_body, body):
    """Short summary of how two bodies differ - line count delta plus the
    first few changed lines, not a full unified diff dump."""
    import difflib
    base_lines = baseline_body.splitlines()
    new_lines = body.splitlines()
    if base_lines == new_lines:
        return None
    sm = difflib.SequenceMatcher(a=base_lines, b=new_lines)
    changed_blocks = [op for op in sm.get_opcodes() if op[0] != "equal"]
    sample = []
    for tag, i1, i2, j1, j2 in changed_blocks[:3]:
        if tag in ("replace", "delete") and i1 < len(base_lines):
            sample.append(f"    - {base_lines[i1][:90]}")
        if tag in ("replace", "insert") and j1 < len(new_lines):
            sample.append(f"    + {new_lines[j1][:90]}")
    return {
        "line_delta": len(new_lines) - len(base_lines),
        "changed_blocks": len(changed_blocks),
        "sample": sample,
    }


def compare_mode():
    """
    Build one request shape (any recipe, or the current path via a plain
    GET), pick which field to vary, then type in a small list of values -
    each one gets sent as its own request and the responses get compared
    against the first as a baseline.
    """
    print("\nCompare mode: pick a recipe shape, then you'll choose one field to vary")
    print("and type in each value to test (blank line when done, need at least 2).\n")

    saved_recipes = load_saved_recipes()
    all_recipes = BUILTIN_RECIPES + saved_recipes

    recipe = None
    if STATE.get("last_recipe"):
        reuse = ask(
            f"Use the same request shape you just sent as the base? [{STATE['last_recipe']['name']}] [Y/n]"
        ).lower()
        if reuse != "n":
            recipe = STATE["last_recipe"]

    if recipe is None:
        cat_choice = choose(
            [(k, label) for k, key, label in CATEGORIES if key not in ("crawl", "bruteenum", "paste")]
            + [("g", "Plain GET on a path (simplest option)")],
            "Which kind of request?",
        )
        if cat_choice is None:
            return

        if cat_choice == "g":
            recipe = {"name": "(plain GET)", "category": "enum", "template": "curl -s -i {scheme}://{target}{path}"}
        else:
            cat_key = category_key_for(cat_choice)
            recipe = recipe_menu(cat_key, all_recipes)
            if recipe is None:
                return

    fields = placeholders_in(recipe["template"])
    if not fields:
        print("This recipe has no fillable fields to vary - pick another.")
        return

    # Put 'path' first if present - it's the most common thing to want to
    # vary (a different endpoint/directory) after reusing a prior request.
    ordered_fields = sorted(fields, key=lambda f: (f != "path",))
    field_opts = [(str(i + 1), f) for i, f in enumerate(ordered_fields)]
    field_choice = choose(field_opts, "Which field should vary across requests?")
    if field_choice is None:
        return
    vary_field = dict(field_opts)[field_choice]

    # Fill every other field once - held constant across all requests.
    # Defaults come straight from the last request's values, so if you're
    # reusing the last recipe you can just hit Enter to keep everything
    # except the one field you're changing.
    base_values = {"target": target_with_port(), "scheme": STATE["scheme"]}
    for field in fields:
        if field == vary_field:
            continue
        default = STATE["last_values"].get(field, "")
        example = FIELD_EXAMPLES.get(field)
        base_values[field] = prompt(field, default=default, example=example)
        STATE["last_values"][field] = base_values[field]

    print(f"\nNow enter values to test for '{vary_field}' - one per line, blank line to stop.")
    example = FIELD_EXAMPLES.get(vary_field)
    if example:
        print(f"(e.g. {example})")
    test_values = []
    while True:
        v = input(PROMPT_STR).strip()
        if not v:
            break
        test_values.append(v)
    if len(test_values) < 2:
        print("Need at least 2 values to compare - back to the menu.")
        return

    commands = []
    for v in test_values:
        values = dict(base_values)
        values[vary_field] = v
        try:
            commands.append((v, recipe["template"].format(**values)))
        except (KeyError, ValueError, IndexError) as e:
            print(f"⚠ Skipping '{v}' - couldn't build the command ({e}).")

    if len(commands) < 2:
        print("Not enough valid commands to compare.")
        return

    confirm = ask(f"About to send {len(commands)} requests, one per value. Run them? [Y/n]").lower()
    if confirm == "n":
        return

    results = []
    for v, cmd in commands:
        print(f"\n$ {cmd}")
        r = run_compare_command(cmd)
        if r is None:
            continue
        r["value"] = v
        results.append(r)
        log_history(cmd)

    if len(results) < 2:
        print("\nNot enough responses came back to compare.")
        return

    baseline = results[0]
    print(f"\nBaseline value: '{baseline['value']}'  ->  status {baseline['status']}, "
          f"size {baseline['size']}, time {baseline['time']}s")

    print(f"\n{'value':<20} {'status':<8} {'size':<10} {'time':<8} {'vs baseline'}")
    print("-" * 70)
    for r in results:
        vs = "-- baseline --" if r is baseline else ""
        if r is not baseline:
            bits = []
            if r["status"] != baseline["status"]:
                bits.append(f"status {baseline['status']}→{r['status']}")
            if r["size"] is not None and baseline["size"] is not None and r["size"] != baseline["size"]:
                bits.append(f"size {baseline['size']}→{r['size']}")
            vs = ", ".join(bits) if bits else "same status/size"
        print(f"{r['value']:<20} {str(r['status']):<8} {str(r['size']):<10} {str(r['time']):<8} {vs}")

    print("\nBody differences vs baseline:")
    any_diff = False
    for r in results:
        if r is baseline:
            continue
        d = diff_bodies(baseline["body"], r["body"])
        if d is None:
            print(f"  '{r['value']}': identical body to baseline")
            continue
        any_diff = True
        print(f"  '{r['value']}': {d['changed_blocks']} changed block(s), "
              f"{d['line_delta']:+d} line(s) vs baseline")
        for line in d["sample"]:
            print(line)

    if not any_diff:
        print("  No response bodies differed from the baseline.")
    print("\nA response that varies (status, size, timing, or body) is a signal worth")
    print("confirming manually - not proof on its own. Each response was also scanned")
    print("for the usual signals/flags above as it came in.")

    # Run the existing signal/vuln scanners against each non-identical
    # response so anything interesting still surfaces per-value.
    for r in results:
        vulns = suggest_vulns(r["status"], r["headers"], r["body"], {vary_field: r["value"]})
        if vulns:
            print(f"\n  Flags for '{r['value']}':")
            for line_no, snippet, tag, hint in vulns:
                print_vuln_flag(line_no, snippet, tag, hint)
                save_finding(line_no, snippet, tag, hint, r["command"])

    STATE["last_command"] = commands[-1][1]
    STATE["last_recipe"] = recipe


def run_command(command, request_values=None):
    """
    The full interactive build-and-send cycle: show the command, explain
    its flags, offer to tweak it, confirm, then execute.
    """
    print(f"\n$ {command}\n")
    explain_command(command)

    extra = prompt(
        "\nAdd extra raw curl flags before sending? (blank to skip)",
        example="-v --max-time 5",
    )
    if extra:
        command = command.replace("curl ", f"curl {extra} ", 1)
        print(f"\n$ {command}\n")
        explain_command(command)

    confirm = ask("Run this? [Y/n]").lower()
    if confirm == "n":
        return

    status_code, headers = execute_and_report(command, request_values)

    if status_code is not None:
        print("That's the full response - your call on what to do next from the menu.")
        offer_inspection_menu(status_code, headers)
    else:
        ask("(Enter to return to the menu)")


def offer_save(recipe, command, values, saved_recipes):
    ans = ask("\nSave this as a new recipe? [y/N]").lower()
    if ans != "y":
        return
    name = prompt("Name for this recipe", default=recipe["name"] + " (custom)")
    template = recipe["template"]
    new_recipe = {"name": name, "category": recipe["category"], "template": template}
    saved_recipes.append(new_recipe)
    save_recipes(saved_recipes)
    print(f"Saved '{name}' to {STORE_FILE}")


def repeat_edit_last():
    """
    Re-send the exact same request shape as last time, with every field
    already defaulted to the value you used last - hit Enter through
    anything unchanged, and only type over the one thing you want to
    change (a different path, a different id, etc). This is the fastest
    path back into a request you already built once.
    """
    recipe = STATE.get("last_recipe")
    if recipe is None:
        print("\nNo previous request to repeat yet - run one first.")
        return
    print(f"\nRepeating: {recipe['name']}  (blank/Enter keeps the previous value shown in [brackets])")
    result = fill_template(recipe)
    if result is None:
        return
    command, values = result
    run_command(command, request_values=values)
    STATE["last_recipe"] = recipe
    offer_save(recipe, command, values, load_saved_recipes())


COMMON_PORTS = ["80", "443", "8080", "8000", "8443", "3000", "5000", "8888", "9000"]


def change_port():
    opts = [(str(i + 1), p) for i, p in enumerate(COMMON_PORTS)]
    opts.append(("c", "Custom port"))
    opts.append(("d", "Default for scheme (clear override)"))
    print(f"\nCurrent port: {STATE['port'] or 'default for ' + STATE['scheme']}")
    choice = choose(opts, "Pick a port:")
    if choice is None:
        return
    if choice == "d":
        STATE["port"] = ""
    elif choice == "c":
        STATE["port"] = prompt("Port number", default=STATE["port"], example="8443")
        if STATE["port"] and not (STATE["port"].isdigit() and 1 <= int(STATE["port"]) <= 65535):
            print(f"  ⚠ '{STATE['port']}' doesn't look like a valid port (1-65535) - double check it")
    else:
        STATE["port"] = COMMON_PORTS[int(choice) - 1]
    print(f"Port set to: {STATE['port'] or 'default for ' + STATE['scheme']}")


def normalize_target(raw):
    working = raw.strip()
    scheme = None
    warnings = []

    m = re.match(r"^(https?)://(.+)$", working, re.IGNORECASE)
    if m:
        scheme = m.group(1).lower()
        working = m.group(2)
        warnings.append(f"saw '{m.group(1)}://' in that - set scheme to {scheme} and stripped it from the target")

    split = re.split(r"[/?]", working, maxsplit=1)
    working = split[0]
    if len(split) > 1 and split[1]:
        warnings.append(f"stripped a trailing path ('/{split[1]}') - target should be host[:port] only, set the path per-recipe instead")

    working = working.rstrip("/")

    if working.count(":") == 1:
        _, port_part = working.split(":")
        if not port_part.isdigit() or not (1 <= int(port_part) <= 65535):
            warnings.append(f"'{port_part}' after the colon doesn't look like a valid port (1-65535) - double check it")
    elif working.count(":") > 1:
        warnings.append("multiple colons detected - if this is IPv6, wrap it in brackets like [::1]:8080")

    return working, scheme, warnings


def get_target_input(prompt_text, default=None, allow_back=False):
    """Returns the cleaned-up target, or None if allow_back=True and the
    user typed 'b' to bail back out to the caller instead of entering one."""
    while True:
        hint = f"{prompt_text} (or 'b' to go back to the main menu)" if allow_back else prompt_text
        raw = prompt(hint, default=default, example="10.10.11.42 or http://10.10.11.42:8080")
        if allow_back and raw.strip().lower() == "b":
            return None
        if not raw:
            print("Target can't be empty - try again.")
            continue
        working, scheme, warnings = normalize_target(raw)
        if not working:
            print("Couldn't find a usable host in that - try again.")
            continue
        for w in warnings:
            print(f"  ⚠ auto-corrected: {w}")
        if scheme:
            STATE["scheme"] = scheme
        return working


# --- crawl / enum mode -------------------------------------------------

LINK_ATTR_RE = re.compile(r'''(?:href|src|action)\s*=\s*["']([^"'#][^"']*)["']''', re.IGNORECASE)
JS_STRING_PATH_RE = re.compile(r'''["'](/[a-zA-Z0-9_\-./]{2,})["']''')

BUILTIN_WORDLIST = [
    "admin", "administrator", "login", "logout", "api", "api/v1", "api/v2",
    "graphql", "swagger", "swagger.json", "openapi.json", "backup", "backups",
    "config", "config.php", ".env", "robots.txt", "sitemap.xml", ".git/HEAD",
    "uploads", "console", "debug", "status", "health", "actuator", "test",
    "dev", "internal", "users", "user", "register", "reset-password",
]


def sitemap_file(target):
    safe = re.sub(r"[^\w.-]", "_", target)
    return STORE_DIR / f"sitemap_{safe}.json"


def load_sitemap():
    f = sitemap_file(target_with_port())
    if not f.exists():
        return []
    try:
        return json.loads(f.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def save_sitemap(entries):
    STORE_DIR.mkdir(exist_ok=True)
    sitemap_file(target_with_port()).write_text(json.dumps(entries, indent=2))


def record_discoveries(paths, source):
    entries = load_sitemap()
    known = {e["path"] for e in entries}
    for p in paths:
        if p not in known:
            entries.append({"path": p, "source": source})
            known.add(p)
    save_sitemap(entries)
    return entries


def target_with_port():
    port_part = f":{STATE['port']}" if STATE["port"] else ""
    return f"{STATE['target']}{port_part}"


def base_url():
    return f"{STATE['scheme']}://{target_with_port()}"


def cookie_jar_flag():
    return "-b cookies.txt " if Path("cookies.txt").exists() else ""


def fetch_body(path):
    cmd = f"curl -s -L {cookie_jar_flag()}{base_url()}{path}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def extract_paths(text):
    found = set()
    for m in LINK_ATTR_RE.finditer(text):
        found.add(m.group(1))
    for m in JS_STRING_PATH_RE.finditer(text):
        found.add(m.group(1))

    normalized = set()
    for link in found:
        if link.startswith(("javascript:", "mailto:", "data:", "#")):
            continue
        if link.startswith("http"):
            parsed = urllib.parse.urlparse(link)
            if parsed.netloc and STATE["target"] not in parsed.netloc:
                continue
            normalized.add(parsed.path or "/")
        elif link.startswith("/"):
            normalized.add(link)
    return normalized


def crawl_mode():
    path = prompt("Path to crawl", default=STATE["last_values"].get("path", "/"), example="/")
    STATE["last_values"]["path"] = path
    print(f"\nFetching {base_url()}{path} ...")
    body = fetch_body(path)
    if not body:
        print("Empty response - check the target/path and try again.")
        return

    paths = sorted(extract_paths(body))
    if not paths:
        print("Nothing extracted from that page.")
        return

    print(f"\nDiscovered {len(paths)} paths:")
    for i, p in enumerate(paths, 1):
        print(f"  {i}) {p}")

    record_discoveries(paths, source="crawl")
    offer_investigate(paths)


def enum_mode():
    wordlist = BUILTIN_WORDLIST
    custom = prompt(
        "Custom wordlist path (blank = built-in list)",
        example="/usr/share/wordlists/dirb/common.txt",
    )
    if custom:
        p = Path(custom).expanduser()
        if p.exists():
            wordlist = [w.strip() for w in p.read_text().splitlines() if w.strip()]
        else:
            print("File not found - using built-in list.")

    print(f"\nProbing {len(wordlist)} paths against {base_url()} ...")
    cookie_flag = cookie_jar_flag()
    hits = []
    for word in wordlist:
        path = "/" + word.lstrip("/")
        cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {cookie_flag}{base_url()}{path}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        code = result.stdout.strip()
        if code and code not in ("000", "404"):
            hits.append(path)
            print(f"  {code}  {path}")

    if not hits:
        print("Nothing interesting in that wordlist.")
        return

    record_discoveries(hits, source="enum")
    offer_investigate(hits)


def auto_scan():
    """
    The fast path from 'here's a target' to 'here's what's worth testing'.
    Crawls a starting page for links, optionally also probes the common
    backend-path wordlist, then sends one plain GET to every path found
    and runs the same line-level vuln scanner used everywhere else in the
    tool against each response - all in one pass, with one findings
    summary at the end instead of checking each result by hand.

    Still fully passive: every request is a plain GET, nothing is ever
    injected or mutated to provoke a response - this is the existing
    crawl + enum + flag pipeline chained together, not a new capability.
    You confirm once before the batch of requests goes out, same as enum
    mode already does.
    """
    print("\nAuto-scan: crawl a page, optionally probe common paths, then check")
    print("every path found for the same signals the rest of the tool looks for.\n")

    start_path = prompt("Starting path to crawl", default=STATE["last_values"].get("path", "/"), example="/")
    STATE["last_values"]["path"] = start_path
    include_enum = yn_prompt("Also probe the built-in common-paths wordlist?", default=True)

    print(f"\nCrawling {base_url()}{start_path} ...")
    body = fetch_body(start_path)
    crawled = sorted(extract_paths(body)) if body else []
    print(f"  found {len(crawled)} link(s) on that page" if crawled else "  nothing extracted from that page")

    all_paths = set(crawled)
    all_paths.add(start_path)

    if include_enum:
        cookie_flag = cookie_jar_flag()
        print(f"\nProbing {len(BUILTIN_WORDLIST)} common paths ...")
        for word in BUILTIN_WORDLIST:
            path = "/" + word.lstrip("/")
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {cookie_flag}{base_url()}{path}"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            except OSError:
                continue
            code = result.stdout.strip()
            if code and code not in ("000", "404"):
                print(f"  {code}  {path}")
                all_paths.add(path)

    all_paths = sorted(all_paths)
    record_discoveries(all_paths, source="scan")

    print(f"\n{len(all_paths)} path(s) to check:")
    for p in all_paths:
        print(f"  {p}")

    if not yn_prompt(f"\nSend a GET to each of these {len(all_paths)} path(s) and scan the responses?", default=True):
        return

    cookie_flag = cookie_jar_flag()
    findings_by_path = {}
    last_cmd = None
    for path in all_paths:
        cmd = f"curl -s -i {cookie_flag}{base_url()}{path}"
        last_cmd = cmd
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        except OSError as e:
            print(f"  ⚠ {path}: couldn't run curl ({e})")
            continue
        log_history(cmd)
        if not result.stdout:
            print(f"  {path}: no response")
            continue
        status, headers, resp_body = parse_response(result.stdout)
        vulns = suggest_vulns(status, headers, resp_body, {"path": path})
        if vulns:
            print(f"  ⚑ {path}  (status {status}) - {len(vulns)} flag(s)")
            findings_by_path[path] = vulns
            for line_no, snippet, tag, hint in vulns:
                save_finding(line_no, snippet, tag, hint, cmd)
        else:
            print(f"  {path}  (status {status}) - nothing flagged")

    if last_cmd:
        STATE["last_command"] = last_cmd

    if not findings_by_path:
        print("\nNothing flagged across any of the paths checked.")
        print("That doesn't mean it's clean - just that nothing matched the patterns this tool knows.")
        return

    total = sum(len(v) for v in findings_by_path.values())
    print(f"\n{'=' * 60}")
    print(f"SCAN SUMMARY - {total} flag(s) across {len(findings_by_path)} path(s)")
    print("=" * 60)
    for path, vulns in findings_by_path.items():
        print(f"\n{path}")
        for line_no, snippet, tag, hint in vulns:
            print_vuln_flag(line_no, snippet, tag, hint)

    print(f"\nAll of this is also saved to {FINDINGS_FILE} - view/mark items anytime with 'f' at the main menu.")


def offer_investigate(paths):
    ans = prompt("\nTest one of these further? (number, or blank to skip)", default="")
    if not ans:
        return
    try:
        chosen = paths[int(ans) - 1]
    except (ValueError, IndexError):
        print("Not a valid choice.")
        return
    STATE["last_values"]["path"] = chosen
    print(f"'{chosen}' is now the default path - pick a recipe to test it against.")


def show_sitemap():
    entries = load_sitemap()
    if not entries:
        print("\nNo discoveries saved for this target yet - try crawl or enum mode.")
        return
    print(f"\nKnown paths for {target_with_port()} ({len(entries)}):")
    for i, e in enumerate(entries, 1):
        print(f"  {i}) {e['path']}  [{e['source']}]")
    offer_investigate([e["path"] for e in entries])


def paste_import():
    print("\nPaste a full curl command (single line).")
    print("Tip: any {word} you type becomes a field you'll be prompted for.")

    def collect_paste():
        raw_in = input(PROMPT_STR).strip()
        if raw_in:
            STATE["last_pasted"] = raw_in
        return raw_in

    raw = with_reuse("Reuse the last command you pasted here?", STATE.get("last_pasted"), collect_paste, default=False)
    if not raw:
        return

    working = raw
    literal_base = f"{STATE['scheme']}://{target_with_port()}"
    if STATE["target"] and literal_base in working:
        working = working.replace(literal_base, "{scheme}://{target}")
    elif STATE["target"] and STATE["target"] in working:
        working = working.replace(target_with_port(), "{target}")

    if working != raw:
        print(f"\nAuto-swapped your current target/scheme for placeholders:\n{working}\n")

    cat_choice = choose(
        [(k, label) for k, key, label in CATEGORIES if key not in ("crawl", "bruteenum", "paste")],
        "Which category does this belong to?",
    )
    cat_key = category_key_for(cat_choice) if cat_choice else "raw"

    recipe = {"name": "(pasted command)", "category": cat_key, "template": working}
    result = fill_template(recipe)
    if result is None:
        return
    command, values = result

    run_command(command, request_values=values)
    STATE["last_recipe"] = recipe
    offer_save(recipe, command, values, load_saved_recipes())


def quick_look():
    path = prompt("Path for the quick look", default=STATE["last_values"].get("path", "/"), example="/")
    STATE["last_values"]["path"] = path
    STATE["last_recipe"] = {"name": "(quick look)", "category": "enum", "template": "curl -s -i {scheme}://{target}{path}"}
    run_command(f"curl -s -i {base_url()}{path}", request_values={"path": path})


def raw_builder():
    print("\nFull request builder - set each part, blank to skip any of them.\n")
    last = STATE.get("last_raw")  # dict of everything used last time in this builder, or None

    method_opts = [
        ("1", "GET"), ("2", "POST"), ("3", "PUT"), ("4", "DELETE"),
        ("5", "PATCH"), ("6", "HEAD"), ("7", "OPTIONS"), ("8", "Custom method"),
    ]

    def pick_method():
        choice = choose(method_opts, "HTTP method:")
        if choice is None:
            return None
        if choice == "8":
            return prompt("Custom method", example="TRACE").strip().upper() or "GET"
        return dict(method_opts)[choice]

    if last:
        http_method = with_reuse(f"Same HTTP method as last time ({last['method']})?", last["method"], pick_method)
    else:
        http_method = pick_method()
    if http_method is None:
        return

    path = prompt("Path", default=STATE["last_values"].get("path", "/"), example="/api/v1/users")
    STATE["last_values"]["path"] = path

    def collect_headers():
        print("\nHeaders - add one at a time, blank line to stop.")
        hs = []
        while True:
            h = prompt("Header", example="Authorization: Bearer <token>")
            if not h:
                break
            hs.append(h)
        return hs

    if last:
        headers = with_reuse(
            f"Reuse the same {len(last['headers'])} header(s) as last time?" if last["headers"] else "Same headers as last time (none)?",
            last["headers"], collect_headers,
        )
    else:
        headers = collect_headers()

    cookie = prompt(
        "Cookie header (blank to skip)",
        default=STATE["last_values"].get("cookie", ""),
        example="PHPSESSID=abc123",
    )
    if cookie:
        STATE["last_values"]["cookie"] = cookie

    def collect_body():
        body_choice = choose(
            [("1", "No body"), ("2", "Form data (key=value&key2=value2)"), ("3", "Raw JSON"), ("4", "Raw/custom data")],
            "Body:",
        )
        if body_choice == "2":
            return prompt("Form data", example="username=admin&password=admin"), False
        if body_choice == "3":
            return prompt("JSON body", example='{"username":"admin"}'), True
        if body_choice == "4":
            return prompt("Raw data", example="anything"), False
        return "", False

    if last and last["body"]:
        body, is_json = with_reuse(
            f"Reuse the same body as last time ({last['body'][:40]!r})?", (last["body"], last["is_json"]), collect_body
        )
    else:
        body, is_json = collect_body()

    follow_redirects = yn_prompt("Follow redirects with -L?", default=last["follow_redirects"] if last else False)
    insecure = yn_prompt("Skip TLS verification with -k?", default=last["insecure"] if last else False)

    parts = ["curl", "-s", "-i", "-X", http_method]
    for h in headers:
        parts.append(f"-H '{h}'")
    if cookie:
        parts.append(f"-b '{cookie}'")
    if body:
        if is_json:
            parts.append("-H 'Content-Type: application/json'")
        parts.append(f"-d '{body}'")
    if follow_redirects:
        parts.append("-L")
    if insecure:
        parts.append("-k")
    parts.append(f"{base_url()}{path}")

    command = " ".join(parts)
    literal_base = f"{STATE['scheme']}://{target_with_port()}"
    reusable_template = command.replace(literal_base, "{scheme}://{target}")

    STATE["last_raw"] = {
        "method": http_method, "headers": headers, "body": body,
        "is_json": is_json, "follow_redirects": follow_redirects, "insecure": insecure,
    }

    run_command(command, request_values={"path": path, "body": body, "cookie": cookie})
    recipe_stub = {"name": "(built manually)", "category": "raw", "template": reusable_template}
    STATE["last_recipe"] = recipe_stub
    offer_save(recipe_stub, command, {}, load_saved_recipes())


BANNER = r"""
 ____    _    ____  _  ______  _   _ ____  _
|  _ \  / \  |  _ \| |/ /  _ \| | | |  _ \| |
| | | |/ _ \ | |_) | ' /| |_) | | | | |_) | |
| |_| / ___ \|  _ <| . \|  __/| |_| |  _ <| |___
|____/_/   \_\_| \_\_|\_\_|    \___/|_| \_\_____|

CURL NATIVE HTTP RECON & INSPECTION WORKFLOW TOOL
      
     "Deeper into the Depths, we must go"
          Created By: Mal3vantCtrl
"""

BOOT_SEQUENCE = [
    "[+] DARKPURL initialized",
    "[+] Loading curl engine",
    "[+] Loading workflow modules",
    "[+] Target handler ready",
]

MENU_PREVIEW = [
    ("a", "Auto-scan", "Crawl a page, hit every path found, and flag anything worth checking - fastest way to go from target to findings."),
    ("0", "Quick look", "One plain GET request - the fastest way to see what a website sends back."),
    ("1", "Login portal test", "Try logging in - normal form login, saving a cookie, NTLM, or basic auth."),
    ("2", "API check", "Send a request to an API - with a token, a JSON body, or a custom header."),
    ("3", "Check a path", "Check if a page/file exists, see its headers and content, follow redirects, skip TLS checks."),
    ("4", "Custom value test", "Put a value of your choosing into a URL param, form field, or header."),
    ("5", "Session / cookie test", "Send a specific cookie, reuse a saved login, or try swapping a cookie's value."),
    ("6", "Saved custom requests", "Anything you've built with the full request builder or saved from a paste - empty until you save one."),
    ("7", "Crawl mode", "Pull every link/API path out of one page and build a map of the site."),
    ("8", "Enum mode", "Try a list of common file/folder names against the target, see what exists."),
    ("9", "Paste a curl command", "Copied a curl command from your browser or Burp? Paste it in and reuse it."),
    ("r", "Full request builder", "Build a request piece by piece - method, headers, cookies, body."),
    ("c", "Compare mode", "Send the same request several times with one thing changed, see what's different."),
    ("e", "Repeat/edit last request", "Re-send your last request with everything pre-filled in - shows up after your first request."),
    ("m", "Sitemap", "Every page/path this tool has found on the current target so far."),
    ("f", "Findings log", "Everything flagged as worth checking so far - mark items off as you confirm them."),
    ("h", "Command history", "Every curl command you've actually run, searchable."),
    ("t", "Change target", "Point the tool at a different host or IP."),
    ("s", "Switch scheme", "Toggle between http and https."),
    ("p", "Change port", "Set or clear a specific port to use."),
    ("x", "Beginner explanations", "Toggle plain-English 'what this means' notes on flagged findings (on by default)."),
]


def show_menu_preview():
    """
    Browse the menu without a target set: shows a bare list of options
    (no descriptions), lets the user pick one to read what it does, then
    offers to go back to the list, back to the main menu, or run that
    option right now. Returns the picked key only if 'run it now' was
    chosen and a real menu action exists for it - otherwise None.
    """
    while True:
        clear_screen()
        print(BANNER)
        print("Pick an option to see what it does.\n")
        opts = [(key, name) for key, name, _ in MENU_PREVIEW]
        choice = choose(opts, "Menu options:", allow_back=False)

        name = dict((k, n) for k, n, _ in MENU_PREVIEW)[choice]
        desc = dict((k, d) for k, _, d in MENU_PREVIEW)[choice]
        clear_screen()
        print(BANNER)
        print(f"{choice}) {name}\n")
        print(f"  {desc}\n")

        next_choice = choose(
            [("1", "Back to the list"), ("2", "Back to main menu"), ("3", f"Use it now")],
            "What next?",
            allow_back=False,
        )
        if next_choice == "1":
            continue
        if next_choice == "3":
            return choice
        return None


def dispatch_action(top_choice):
    """
    Run one top-level menu action given its key. This is the single place
    that maps a menu key to what actually happens - used by the normal
    menu loop, and also by 'Use it now' from the menu preview when it's
    picked before a target has even been entered (the target gets set
    first, then this runs immediately after instead of dropping the user
    back at the welcome screen with nothing having happened).
    """
    saved_recipes = load_saved_recipes()
    all_recipes = BUILTIN_RECIPES + saved_recipes

    if top_choice == "a":
        auto_scan()
        return
    if top_choice == "t":
        STATE["target"] = get_target_input("New target", default=STATE["target"])
        return
    if top_choice == "s":
        STATE["scheme"] = "https" if STATE["scheme"] == "http" else "http"
        return
    if top_choice == "x":
        STATE["beginner_mode"] = not STATE["beginner_mode"]
        return
    if top_choice == "p":
        change_port()
        return
    if top_choice == "c":
        compare_mode()
        return
    if top_choice == "e":
        repeat_edit_last()
        return
    if top_choice == "m":
        show_sitemap()
        return
    if top_choice == "f":
        show_findings()
        return
    if top_choice == "h":
        show_history()
        return
    if top_choice == "7":
        crawl_mode()
        return
    if top_choice == "8":
        enum_mode()
        return
    if top_choice == "9":
        paste_import()
        return
    if top_choice == "0":
        quick_look()
        return
    if top_choice == "r":
        raw_builder()
        return

    cat_key = category_key_for(top_choice)
    recipe = recipe_menu(cat_key, all_recipes)
    if recipe is None:
        return

    result = fill_template(recipe)
    if result is None:
        return
    command, values = result

    run_command(command, request_values=values)
    STATE["last_recipe"] = recipe
    offer_save(recipe, command, values, saved_recipes)


def main():
    clear_screen()
    print(BANNER)
    for line in BOOT_SEQUENCE:
        print(line)
        time.sleep(0.35)
    time.sleep(0.5)

    pending_action = None
    while True:
        clear_screen()
        print(BANNER)
        print("(press q at any menu to quit)")
        print("New here? When something's flagged as a possible issue, this tool adds a plain-English")
        print("note explaining what it means and why it matters - ON by default, toggle with 'x' in the menu.\n")

        entry_choice = choose(
            [
                ("1", "Find vulnerabilities fast (auto-scan)"),
                ("2", "View menu options"),
            ],
            "Main menu:",
            allow_back=False,
        )
        if entry_choice == "2":
            picked = show_menu_preview()
            if picked is None:
                continue
            pending_action = picked
        elif entry_choice == "1":
            pending_action = "a"

        clear_screen()
        print(BANNER)
        print("Let's get started - point DARKPURL at a target.\n")
        target = get_target_input("Target (host or IP - you can type host:port here too)", allow_back=True)
        if target is None:
            pending_action = None
            continue
        STATE["target"] = target
        break

    if pending_action:
        dispatch_action(pending_action)

    while True:
        top_choice = category_menu()
        if top_choice == "?":
            picked = show_menu_preview()
            if picked is None:
                continue
            top_choice = picked  # fall through - handled the same as if just chosen
        dispatch_action(top_choice)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nbye")
