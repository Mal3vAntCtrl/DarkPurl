# DarkPurl

> **curl-native HTTP inspection & workflow tool for penetration testing and CTFs.**

---

## 🚧 Project Status

Changelog
v2.0.0 – Auto-Scan & Vulnerability Flagging Release

(previously: v1.0 – Early Release)

Added

Auto-scan (a) — the new headline feature. Crawls a starting page, optionally probes a built-in common-paths wordlist, sends a request to every path found, and runs the full vulnerability scanner against each response — all in one guided pass with a consolidated findings summary at the end. Now offered right on the welcome screen as the fastest path from target to findings.
Line-level vulnerability flagging (suggest_vulns) — passive pattern matching across SQLi (per-dialect), NoSQLi, SSTI (10+ template engines), LDAP/XPath injection, GraphQL error leaks/introspection, OS command injection, LFI/RFI, XXE, insecure deserialization, SSRF hints, JWT issues, framework debug pages (Django/Flask/Laravel/Spring/ASP.NET/Rails/Node), CMS fingerprinting, exposed .git/.env, reflected input, IDOR, cookie hardening gaps, open redirects, and CORS misconfigurations. Every hit points to the exact line and snippet that triggered it.
Plain-English explanations — optional "what this means" note under every flagged finding, aimed at less experienced users. On by default, toggle with x.
Findings log (f) — every flagged issue is persisted to ~/.curlmenu/findings.json per target, with a way to mark items confirmed as you manually verify them.
Compare mode (c) — send the same request shape multiple times with one field varied (you supply the values), and get a status/size/timing table plus a body diff against a baseline — the core technique behind confirming blind SQLi, IDOR, and auth-bypass bugs.
State continuity — the tool now remembers your last recipe, raw-builder settings, and pasted commands. e) Repeat/edit last request re-sends your last request with every field pre-filled. Compare mode and the raw builder offer "same as last time?" shortcuts instead of re-asking everything.
Menu preview / help screen (? or from the welcome screen) — browse what every option does without a target set, drill into one for a plain-language description, then jump straight into it or head back.
Animated boot sequence and a cleaner welcome flow — entering a target is now its own screen instead of stacking on top of the previous menu.

Changed

Welcome screen trimmed to two real choices: 1) Find vulnerabilities fast (auto-scan) and 2) View menu options.
Main menu labels shortened to a few words each, with full descriptions moved behind the ? preview screen instead of cluttering the working menu.
Renamed category 3 from "Dir / file enum" to "Check a path" to stop it being confused with 8) Enum mode (actual wordlist-based path discovery) — these were doing very different things under near-identical names.
Category 6 renamed to "Saved custom requests" — its only built-in recipe was removed (see below) so it's now purely the bucket for anything you build with the full request builder or save from a pasted command.
detect_signals() narrowed to header/status-only signals; all body-level flagging (stack traces, verbose errors, directory listings, etc.) now goes through the single suggest_vulns() pipeline instead of being reported twice in slightly different words.
Removed the emoji from the main menu labels for terminal compatibility.

Fixed / Removed

Removed the "Freeform curl (you type the rest)" built-in recipe — it duplicated the "Add extra raw curl flags before sending?" prompt that already runs on every request regardless of recipe.
Added a b-to-go-back escape hatch at the target-entry prompt so choosing "enter a target" doesn't strand you with no way back to the welcome screen.
Fixed "Use it now" from the menu preview doing nothing when picked before a target was set — it now takes you straight to target entry and runs the chosen action immediately afterward.
---

## Overview

DarkPurl is an interactive, menu-driven wrapper around `curl` that simplifies common HTTP reconnaissance and testing workflows. Instead of remembering lengthy command-line syntax, DarkPurl guides you through building requests, inspecting responses, and replaying common attack scenarios through an intuitive interface.

Designed for penetration testers, students, and CTF players, DarkPurl streamlines repetitive web testing tasks while remaining lightweight and dependency-free.

---

## Features

* Interactive menu-driven interface
* Built on native `curl`
* HTTP request inspection and analysis
* Common penetration testing and CTF workflows
* Built-in request recipes
* Create and save custom recipes
* Display generated `curl` commands before execution
* Lightweight with no external dependencies

---

## Requirements

* Python 3.8+
* `curl`

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Mal3vAntCtrl/DarkPurl.git
cd DarkPurl
```

Run the tool:

```bash
python3 darkpurl.py
```

---

## Example Workflow

1. Enter the target host or IP address.
2. Select a workflow category.
3. Choose a built-in recipe.
4. Provide only the required information.
5. Review the generated `curl` command.
6. Execute the request and inspect the response.
7. Save customized workflows for future use.

---

## Example Use Cases

* Web application reconnaissance
* HTTP endpoint testing
* Authentication testing
* API exploration
* Header inspection
* Cookie analysis
* CTF web challenges
* Learning and practicing `curl`

---

## Roadmap

### Completed (v1.0)

* ✅ Interactive menu-driven interface
* ✅ curl-native HTTP workflows
* ✅ Built-in workflow recipes
* ✅ Custom recipe persistence
* ✅ Request preview before execution
* ✅ Response inspection

### Planned

* ⏳ Colorized response output
* ⏳ Session and cookie management
* ⏳ Automatic authentication workflows
* ⏳ Request history
* ⏳ Header and parameter fuzzing helpers
* ⏳ JSON response formatting
* ⏳ Proxy support
* ⏳ Export and import workflows
* ⏳ Additional pentesting and CTF recipes
* ⏳ Improved UI and usability enhancements

---

## Philosophy

DarkPurl focuses on making HTTP testing fast, repeatable, and transparent. Every generated request is displayed before execution so users understand exactly what is being sent while reducing the need to memorize complex `curl` syntax.

The goal is not to replace `curl`, but to make it easier to learn, faster to use, and more accessible during web assessments and CTFs.

---

## Contributing

DarkPurl is an actively evolving project. Contributions, bug reports, feature requests, and workflow suggestions are appreciated and help shape future releases.

---

## Disclaimer

This project is intended for authorized security testing, educational purposes, and Capture The Flag (CTF) environments only. Always obtain proper authorization before testing systems you do not own or have permission to assess.

---

## Author

**MAL3VANTCTRL**
