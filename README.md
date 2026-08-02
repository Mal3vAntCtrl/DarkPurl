# DarkPurl

> **curl-native HTTP inspection & workflow tool for penetration testing and CTFs.**

DarkPurl is an interactive, menu-driven wrapper around `curl` that simplifies common HTTP reconnaissance and testing workflows. Instead of remembering lengthy command-line syntax, DarkPurl guides you through building requests, inspecting responses, and replaying common attack scenarios from an easy-to-use interface.

Designed for penetration testers, students, and CTF players, DarkPurl helps streamline repetitive web testing tasks while remaining lightweight and dependency-free.

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
git clone https://github.com/<your-username>/DarkPurl.git
cd DarkPurl
```

Run the tool:

```bash
python3 darkpurl.py
```

---

## Example Workflow

1. Specify a target host or IP.
2. Select a workflow category.
3. Choose a built-in recipe.
4. Provide only the required fields.
5. Review the generated `curl` command.
6. Execute and inspect the response.
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

## Philosophy

DarkPurl focuses on making HTTP testing fast, repeatable, and transparent. Every generated request is shown before execution, allowing users to understand exactly what is being sent while reducing the need to memorize complex `curl` syntax.

---

## Disclaimer

This project is intended for authorized security testing, educational purposes, and CTF environments only. Always obtain permission before testing systems you do not own.

---

## Author

**MAL3VANTCTRL**
