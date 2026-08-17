# Changelog

## v2.0.0 – Auto-Scan & Vulnerability Flagging Release

*Previously: v1.0 – Early Release*

### Added

**Auto-scan (a)** — The new headline feature. Crawls a starting page, optionally probes a built-in common-paths wordlist, sends a request to every path found, and runs the full vulnerability scanner against each response — all in one guided pass with a consolidated findings summary at the end. Now offered right on the welcome screen as the fastest path from target to findings.

**Line-level vulnerability flagging (`suggest_vulns`)** — Passive pattern matching across SQLi (per-dialect), NoSQLi, SSTI (10+ template engines), LDAP/XPath injection, GraphQL error leaks/introspection, OS command injection, LFI/RFI, XXE, insecure deserialization, SSRF hints, JWT issues, framework debug pages (Django/Flask/Laravel/Spring/ASP.NET/Rails/Node), CMS fingerprinting, exposed `.git`/`.env`, reflected input, IDOR, cookie hardening gaps, open redirects, and CORS misconfigurations. Every hit points to the exact line and snippet that triggered it.

**Plain-English explanations** — Optional "what this means" note under every flagged finding, aimed at less experienced users. On by default, toggle with `x`.

**Findings log (f)** — Every flagged issue is persisted to `~/.curlmenu/findings.json` per target, with a way to mark items confirmed as you manually verify them.

**Compare mode (c)** — Send the same request shape multiple times with one field varied (you supply the values), and get a status/size/timing table plus a body diff against a baseline — the core technique behind confirming blind SQLi, IDOR, and auth-bypass bugs.

**State continuity** — The tool now remembers your last recipe, raw-builder settings, and pasted commands. `e)` Repeat/edit last request re-sends your last request with every field pre-filled. Compare mode and the raw builder offer "same as last time?" shortcuts instead of re-asking everything.

**Menu preview / help screen (`?`)** — Browse what every option does without a target set, drill into one for a plain-language description, then jump straight into it or head back.

**Animated boot sequence and a cleaner welcome flow** — Entering a target is now its own screen instead of stacking on top of the previous menu.

### Changed

**Welcome screen** — Trimmed to two real choices: **1) Find vulnerabilities fast (auto-scan)** and **2) View menu options**.

**Main menu** — Labels shortened to a few words each, with full descriptions moved behind the `?` preview screen instead of cluttering the working menu.

**Category 3** — Renamed from **"Dir / file enum"** to **"Check a path"** to stop it being confused with **8) Enum mode** (actual wordlist-based path discovery). These were doing very different things under near-identical names.

**Category 6** — Renamed to **"Saved custom requests"**. Its only built-in recipe was removed (see below), so it's now purely the bucket for anything you build with the full request builder or save from a pasted command.

**`detect_signals()`** — Narrowed to header/status-only signals. All body-level flagging (stack traces, verbose errors, directory listings, etc.) now goes through the single `suggest_vulns()` pipeline instead of being reported twice in slightly different words.

**Terminal compatibility** — Removed emojis from the main menu labels.

### Fixed / Removed

**Removed the "Freeform curl (you type the rest)" built-in recipe** — It duplicated the "Add extra raw curl flags before sending?" prompt that already runs on every request regardless of recipe.

**Added a `b`-to-go-back escape hatch** at the target-entry prompt so choosing "enter a target" doesn't strand you with no way back to the welcome screen.

**Fixed "Use it now"** from the menu preview doing nothing when picked before a target was set. It now takes you straight to target entry and runs the chosen action immediately afterward.
