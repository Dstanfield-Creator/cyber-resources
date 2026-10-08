# Command Injection

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Command injection occurs when an application passes untrusted input into an
operating-system shell, allowing an actor to run arbitrary commands with the
application's privileges. Impact is typically full host compromise. Detection
hinges on correlating web input with unexpected child-process creation.

Relevant MITRE ATT&CK techniques:

| ID | Name |
| --- | --- |
| T1059 | Command and Scripting Interpreter |
| T1190 | Exploit Public-Facing Application |

Maps to OWASP Top 10 A03 (Injection) and OWASP WSTG command-injection tests.

## How It Works

The application builds a shell command string from user input without
sanitisation, so shell metacharacters (`;`, `|`, `&&`, backticks, `$()`) let the
input break out of the intended command. Signals:

- A web-facing process (e.g. a PHP, Node or Java worker) spawning a shell such as
  `/bin/sh`, `bash`, `cmd.exe` or `powershell.exe`.
- Shell metacharacters appearing in request parameters.
- Follow-on discovery commands (`id`, `whoami`, `uname`, `ipconfig`) immediately
  after a web request.

## Detect

Log sources and signals:

| Source | Signal |
| --- | --- |
| Sysmon 1 / auditd execve | Web service spawning a shell or interpreter |
| Web / WAF logs | Metacharacters and command names in parameters |
| EDR process tree | Unusual parent-child (web worker to shell) |

```yaml
title: Web Service Spawning Shell (Possible Command Injection)
logsource:
    category: process_creation
detection:
    selection:
        ParentImage|endswith:
            - '\w3wp.exe'
            - '/php-fpm'
            - '/node'
            - '/httpd'
        Image|endswith:
            - '/sh'
            - '/bash'
            - '\cmd.exe'
            - '\powershell.exe'
    condition: selection
falsepositives:
    - Applications that legitimately shell out for batch jobs
level: high
```

The web-worker-spawns-shell pattern is high fidelity; enrich with the triggering
request to confirm the input-to-execution link.

## Mitigate

- Avoid invoking the shell entirely; call APIs or libraries instead of commands.
- Where a command is unavoidable, use parameterised exec APIs that pass arguments
  as an array and never through a shell string.
- Validate input against strict allowlists.
- Run web services with least privilege and in constrained containers.
- Alert on web-tier processes spawning interpreters.

## Lab

Isolated lab (deliberately vulnerable app, host-only 192.0.2.0/24):

1. Trigger a benign command (e.g. echo a marker) through your own lab app and
   confirm the parent-child spawn is captured and triggers the Sigma rule.
2. Replace the shell call with a parameterised exec API and verify injection no
   longer executes.
3. Add least-privilege / container isolation and re-assess impact.

## References

- MITRE ATT&CK T1059 - https://attack.mitre.org/techniques/T1059/
- OWASP Command Injection - https://owasp.org/www-community/attacks/Command_Injection
- OWASP Injection Prevention Cheat Sheet - https://cheatsheetseries.owasp.org/
- OWASP Top 10 A03 - https://owasp.org/Top10/

---

**Author:** Danny Stanfield
**License:** MIT
