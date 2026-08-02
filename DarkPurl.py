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
import urllib.parse
from pathlib import Path

STORE_DIR = Path.home() / ".curlmenu"
STORE_FILE = STORE_DIR / "recipes.json"
HISTORY_FILE = STORE_DIR / "history.log"
PROMPT_STR = "DARKPURL > "

STATE = {"target": "", "last_values": {}, "scheme": "http", "port": "", "last_command": ""}

CATEGORIES = [
    ("0", "quicklook", "Quick single request (start here if you're not sure)"),
    ("1", "login", "Login portal test"),
    ("2", "api", "API check"),
    ("3", "enum", "Directory / file enum"),
    ("4", "injection", "Custom value test (query/body/header)"),
    ("5", "session", "Session / cookie test"),
    ("6", "raw", "Raw / custom curl"),
    ("7", "crawl", "Crawl mode (extract links/API paths from a page)"),
    ("8", "bruteenum", "Enum mode (probe common backend paths)"),
    ("9", "paste", "Paste an existing curl command (import)"),
    ("r", "builder", "Full request builder (set method/headers/cookies/body by hand)"),
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
    {
        "name": "Freeform curl (you type the rest)",
        "category": "raw",
        "template": "curl {raw_args} {scheme}://{target}{path}",
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
    # keep order of first appearance, drop duplicates, always exclude
    # "target"/"scheme" - those are set once globally, not per-recipe
    seen = []
    for name in PLACEHOLDER_RE.findall(template):
        if name not in ("target", "scheme") and name not in seen:
            seen.append(name)
    return seen


def ask(text):
    """Print a question/info line, blank space, an input cue, then the prompt."""
    print(f"\n{text}\n")
    print("Your input below:")
    return input(PROMPT_STR).strip()


def prompt(text, default=None, example=None):
    hint = f" (e.g. {example})" if example else ""
    suffix = f" [{default}]" if default else ""
    val = ask(f"{text}{hint}{suffix}")
    return val if val else (default or "")


def choose(options, title, allow_back=True):
    """options: list of (key, label). Returns chosen key, or None if back/quit."""
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
    opts = [(k, label) for k, _, label in CATEGORIES]
    opts.append(("m", "Show known sitemap for this target"))
    opts.append(("h", "Show command history"))
    opts.append(("t", "Change target"))
    opts.append(("s", f"Toggle scheme (currently {STATE['scheme']})"))
    opts.append(("p", f"Change port (currently {STATE['port'] or 'default'})"))
    print(f"Target: {base_url()}")
    return choose(opts, "What would you like to do?", allow_back=False)


def category_key_for(choice_num):
    for k, key, _ in CATEGORIES:
        if k == choice_num:
            return key
    return None


def recipe_menu(cat_key, all_recipes):
    matching = [r for r in all_recipes if r["category"] == cat_key]
    if not matching:
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
    """Print a plain-language breakdown of the flags in a curl command."""
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

BODY_MARKERS = [
    "traceback (most recent call last)",
    "fatal error",
    "warning: ",
    "stack trace",
    "index of /",
    "internal server error",
]


def parse_response(text):
    """Split a curl -i response into (status_code, headers dict, body)."""
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


def detect_signals(status_code, headers, body):
    signals = []
    for h in INTERESTING_HEADERS:
        if h in headers:
            signals.append(f"{h}: {headers[h]}")
    if "set-cookie" in headers:
        signals.append(f"set-cookie: {headers['set-cookie']}")
    if "location" in headers:
        signals.append(f"location (redirect target): {headers['location']}")
    if status_code and status_code >= 500:
        signals.append(f"server error ({status_code}) - body may hold a stack trace worth reading in full")
    if status_code in (401, 403):
        signals.append(f"access denied ({status_code}) - this path likely needs auth")

    body_lower = body.lower()
    for marker in BODY_MARKERS:
        if marker in body_lower:
            signals.append(f"body contains '{marker.strip()}' - looks like verbose/debug error output")
            break

    return signals


def offer_inspection_menu(status_code, headers):
    """
    Fully opt-in entry point. Every option is itself just another curl
    request aimed at understanding structure (methods, redirects,
    verbosity) - nothing here picks a value or fires anything automatically.
    """
    ans = ask("\nWant a menu of inspection follow-ups based on this response? [y/N]").lower()
    if ans != "y":
        return
    inspection_loop(status_code, headers)


def inspection_loop(status_code, headers):
    """The actual options + handling. Separate from the opt-in gate above
    so choosing to keep testing after a follow-up loops back here directly
    instead of re-asking whether you want the menu at all."""
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


def execute_and_report(command):
    """
    Actually run a command and show what came back - no confirmation, no
    tweak prompt, no nested inspection offer. Used for one-click follow-ups
    where the choice to run was already made; re-asking would just be the
    same trap that broke the workflow before (typing a menu-looking answer
    into what was actually a free-text flag prompt).
    Returns (status_code, headers) so the caller can decide what's next.
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

    signals = detect_signals(status_code, headers, body) if result.stdout else []
    if signals:
        print("\nSignals worth noting:")
        for s in signals:
            print(f"  - {s}")

    log_history(command)
    STATE["last_command"] = command
    return status_code, headers


def run_command(command):
    """
    The full interactive build-and-send cycle: show the command, explain
    its flags, offer to tweak it, confirm, then execute. Used whenever the
    command is being newly built (recipes, the request builder, paste
    import, quick-look) - situations where a tweak/confirm step adds real
    value because the request itself is still fresh.
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

    status_code, headers = execute_and_report(command)

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
    # rebuild a template: swap the literal values back out for placeholders
    # so the saved recipe stays reusable, not hardcoded to this one run.
    template = recipe["template"]
    new_recipe = {"name": name, "category": recipe["category"], "template": template}
    saved_recipes.append(new_recipe)
    save_recipes(saved_recipes)
    print(f"Saved '{name}' to {STORE_FILE}")


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
    """
    Accepts messy input (scheme prefix, trailing path, trailing slash) and
    returns (clean_host_or_hostport, detected_scheme_or_None, warnings).
    Never silently changes something without saying so.
    """
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


def get_target_input(prompt_text, default=None):
    while True:
        raw = prompt(prompt_text, default=default, example="10.10.11.42 or http://10.10.11.42:8080")
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

# Heuristic extractors - not a substitute for gobuster/ffuf/burp's crawler,
# but enough to surface obvious links, forms, and JS-embedded API calls
# without leaving the tool.
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
    """The -b flag for reusing a saved cookie jar, if one exists in the cwd."""
    return "-b cookies.txt " if Path("cookies.txt").exists() else ""


def fetch_body(path):
    """GET a path, reusing the cookie jar if one exists from a prior login."""
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
                continue  # off-target, skip
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
    """
    Take a curl command from anywhere (browser devtools 'Copy as cURL',
    Burp's 'Copy as curl command', a writeup, your own terminal history)
    and drop it straight into the tool. The current target/scheme are
    auto-swapped for {target}/{scheme} so it's reusable on the next box;
    you can hand-add other {placeholder} names in the pasted text too.
    """
    print("\nPaste a full curl command (single line).")
    print("Tip: any {word} you type becomes a field you'll be prompted for.")
    raw = input(PROMPT_STR).strip()
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

    run_command(command)
    offer_save(recipe, command, values, load_saved_recipes())


def quick_look():
    """
    The 'start here' move. One plain GET, full response shown, then the
    normal signal-detection + inspection-menu flow takes over from there -
    no knowledge of the target assumed going in.
    """
    path = prompt("Path for the quick look", default=STATE["last_values"].get("path", "/"), example="/")
    STATE["last_values"]["path"] = path
    run_command(f"curl -s -i {base_url()}{path}")


def raw_builder():
    """
    Full manual control over every piece of the request - method, headers,
    cookies, body - assembled one field at a time. For when you already
    know exactly what you want to send and just want to build it fast,
    rather than hunting for the closest-matching named recipe.
    """
    print("\nFull request builder - set each part, blank to skip any of them.\n")

    method_opts = [
        ("1", "GET"), ("2", "POST"), ("3", "PUT"), ("4", "DELETE"),
        ("5", "PATCH"), ("6", "HEAD"), ("7", "OPTIONS"), ("8", "Custom method"),
    ]
    method_choice = choose(method_opts, "HTTP method:")
    if method_choice is None:
        return
    if method_choice == "8":
        http_method = prompt("Custom method", example="TRACE").strip().upper() or "GET"
    else:
        http_method = dict(method_opts)[method_choice]

    path = prompt("Path", default=STATE["last_values"].get("path", "/"), example="/api/v1/users")
    STATE["last_values"]["path"] = path

    print("\nHeaders - add one at a time, blank line to stop.")
    headers = []
    while True:
        h = prompt("Header", example="Authorization: Bearer <token>")
        if not h:
            break
        headers.append(h)

    cookie = prompt(
        "Cookie header (blank to skip)",
        default=STATE["last_values"].get("cookie", ""),
        example="PHPSESSID=abc123",
    )
    if cookie:
        STATE["last_values"]["cookie"] = cookie

    body = ""
    is_json = False
    body_choice = choose(
        [("1", "No body"), ("2", "Form data (key=value&key2=value2)"), ("3", "Raw JSON"), ("4", "Raw/custom data")],
        "Body:",
    )
    if body_choice == "2":
        body = prompt("Form data", example="username=admin&password=admin")
    elif body_choice == "3":
        body = prompt("JSON body", example='{"username":"admin"}')
        is_json = True
    elif body_choice == "4":
        body = prompt("Raw data", example="anything")

    follow_redirects = ask("Follow redirects with -L? [y/N]").lower() == "y"
    insecure = ask("Skip TLS verification with -k? [y/N]").lower() == "y"

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

    run_command(command)
    recipe_stub = {"name": "(built manually)", "category": "raw", "template": reusable_template}
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


def main():
    clear_screen()
    print(BANNER)
    for line in BOOT_SEQUENCE:
        print(line)
    print("(press q at any menu to quit)\n")
    STATE["target"] = get_target_input("Target (host or IP - you can type host:port here too)")

    start = ask("\nNew to this target? Send a quick GET to see what's there first? [Y/n]").lower()
    if start != "n":
        quick_look()

    while True:
        saved_recipes = load_saved_recipes()
        all_recipes = BUILTIN_RECIPES + saved_recipes

        top_choice = category_menu()
        if top_choice == "t":
            STATE["target"] = get_target_input("New target", default=STATE["target"])
            continue
        if top_choice == "s":
            STATE["scheme"] = "https" if STATE["scheme"] == "http" else "http"
            continue
        if top_choice == "p":
            change_port()
            continue
        if top_choice == "m":
            show_sitemap()
            continue
        if top_choice == "h":
            show_history()
            continue
        if top_choice == "7":
            crawl_mode()
            continue
        if top_choice == "8":
            enum_mode()
            continue
        if top_choice == "9":
            paste_import()
            continue
        if top_choice == "0":
            quick_look()
            continue
        if top_choice == "r":
            raw_builder()
            continue

        cat_key = category_key_for(top_choice)
        recipe = recipe_menu(cat_key, all_recipes)
        if recipe is None:
            continue

        result = fill_template(recipe)
        if result is None:
            continue
        command, values = result

        run_command(command)
        offer_save(recipe, command, values, saved_recipes)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nbye")
