# JOCKY Language Reference

JOCKY is a small, declarative language for describing a forensic investigation. A script says
*what* to collect, analyse, verify and report. It never contains shell commands. The compiler
turns it into a typed intermediate representation (IR), and the runtime dispatches only
catalogued, read-only collectors.

```
source ─► lexer ─► parser ─► AST ─► validator ─► IR 2.0 ─► platform backend ─► restricted runtime
```

Try any stage from the command line:

```bash
python jocky.py compile examples/block_audit.jocky                     # human summary
python jocky.py compile examples/block_audit.jocky --emit ir           # IR as JSON
python jocky.py compile examples/block_audit.jocky --platform linux    # lower for Ubuntu
python jocky.py compile examples/block_audit.jocky --emit tokens       # lexer output
```

## Two equivalent forms

**Block form** (blueprint §4.3):

```jocky
investigation "System_Audit_001" {
    target "lab-pc"
    platform detect
    collect system_information
    collect running_processes where status == running
    collect active_network_connections where state == established
    analyze process_network
    verify integrity
    report format html
}
```

**Flat form** (original syntax, still supported):

```jocky
CASE "System_Audit_001"
TARGET "lab-pc"
COLLECT SYSTEM
COLLECT PROCESSES
    WHERE status == RUNNING
COLLECT NETWORK
    WHERE state == ESTABLISHED
ANALYZE PROCESS_NETWORK
VERIFY INTEGRITY
REPORT FORMAT HTML
```

Both compile to the same IR operations. The block name becomes the case identifier.

## Lexical rules

- Keywords are case-insensitive (`collect` = `COLLECT`).
- Strings use double quotes and support `\n`, `\t`, `\"` and `\\` escapes. They cannot span lines.
- Comments start with `#` or `//` and run to the end of the line.
- Statements end at a newline, a `;`, or a closing `}`. Inside a block, a new statement keyword
  also ends the previous statement, so a whole investigation can sit on one line.

## Grammar (EBNF)

```ebnf
script        = { separator } , { ( investigation | statement ) , { separator } } ;
investigation = "investigation" , STRING , "{" , { separator } , { statement , { separator } } , "}" ;
separator     = NEWLINE | ";" ;

statement     = case | target | platform | collect | analyze | verify | report ;
case          = "case" , STRING ;
target        = "target" , STRING ;
platform      = "platform" , ( "detect" | "auto" | "windows" | "linux" | "ubuntu" | "macos" | "darwin" ) ;

collect       = "collect" , ( files | category , [ where ] ) ;
files         = "files" , STRING ;
category      = "system" | "processes" | "network" | "users" | "registry" | "windows_metadata"
              | "services" | "startup" | "drivers" | "listening_ports" | "dns"
              | alias ;
alias         = "system_information" | "system_info" | "running_processes" | "process_list"
              | "active_network_connections" | "active_connections" | "network_connections"
              | "user_accounts" | "local_users" | "installed_services" | "startup_entries"
              | "autostart_entries" | "kernel_modules" | "installed_drivers" | "open_ports"
              | "dns_configuration" | "dns_cache" ;
where         = [ NEWLINE ] , "where" , field , "==" , value ;
field         = "status" | "state" | IDENTIFIER ;
value         = IDENTIFIER | STRING | INTEGER ;

analyze       = "analyze" , [ "process_network" | "detections" | "threats" | "threat_indicators" | IDENTIFIER ] ;
verify        = "verify" , "integrity" ;
report        = "report" , [ "format" , ( "json" | "html" | "md" | "markdown" ) ] ;
```

## Semantic rules

| Rule | Error |
|---|---|
| Exactly one case (`CASE` or an investigation block) | JKY301 / JKY302 |
| Exactly one `TARGET` | JKY303 / JKY304 |
| At most one `PLATFORM` | JKY308 |
| At least one `COLLECT` | JKY307 |
| `WHERE status` only on processes; `WHERE state` only on network | JKY310 |
| Filter values: status ∈ RUNNING, SLEEPING, STOPPED, ZOMBIE, IDLE; state ∈ ESTABLISHED, LISTEN, TIME_WAIT, CLOSE_WAIT, SYN_SENT | JKY311 |
| `VERIFY INTEGRITY` must come after an evidence-producing `COLLECT` | JKY320 |
| Report format is JSON, HTML, MD or MARKDOWN | JKY330 |

## Operation catalog

Every IR operation is stamped with an entry from `backend/app/language/capabilities.py`. A test
keeps this table identical to the runtime allow-list in `backend/app/engine/ir_policy.py`.

| Statement | Capability | Output schema | Platforms |
|---|---|---|---|
| `collect system` | COLLECT_SYSTEM | jocky.system.v1 | Windows, Linux, macOS |
| `collect processes` | COLLECT_PROCESSES | jocky.process_list.v1 | Windows, Linux, macOS |
| `collect network` | COLLECT_NETWORK | jocky.network.v1 | Windows, Linux, macOS |
| `collect files "<path>"` | COLLECT_FILES | jocky.file_list.v1 | Windows, Linux, macOS |
| `collect users` | COLLECT_USERS | jocky.users.v1 | Windows, Linux, macOS |
| `collect services` | COLLECT_SERVICES | jocky.services.v1 | Windows, Linux, macOS |
| `collect startup` | COLLECT_STARTUP | jocky.startup.v1 | Windows, Linux, macOS |
| `collect drivers` | COLLECT_DRIVERS | jocky.drivers.v1 | Windows, Linux |
| `collect listening_ports` | COLLECT_LISTENING_PORTS | jocky.listening_ports.v1 | Windows, Linux, macOS |
| `collect dns` | COLLECT_DNS | jocky.dns.v1 | Windows, Linux, macOS |
| `collect registry` | COLLECT_REGISTRY | jocky.registry.v1 | Windows |
| `collect windows_metadata` | COLLECT_WINDOWS_METADATA | jocky.windows_metadata.v1 | Windows |
| `analyze` / `analyze process_network` | ANALYZE_PROCESS_NETWORK | jocky.analysis.v1 | Windows, Linux, macOS |
| `analyze detections` (alias `threats`) | ANALYZE_DETECTIONS | jocky.detections.v1 | Windows, Linux, macOS |
| `verify integrity` | VERIFY_INTEGRITY | jocky.integrity.v1 | Windows, Linux, macOS |
| `report [format json\|html\|md]` | REPORT_JSON / REPORT_HTML / REPORT_MD | jocky.report.v1 | Windows, Linux, macOS |

`dns` (and its alias `dns_cache`) reads resolver configuration and the hosts file. JOCKY does not
read the Windows DNS client cache, because that needs an undocumented API.

### What each inventory source reads

| Source | Windows | Linux | macOS |
|---|---|---|---|
| services | Service Control Manager (psutil) | systemd unit files, enabled via `*.wants` links | LaunchDaemons |
| startup | HKLM/HKCU Run and RunOnce, Startup folders | cron (system and per-user), XDG autostart, rc.local | LaunchAgents |
| drivers | `HKLM\SYSTEM\CurrentControlSet\Services` with driver Type | `/proc/modules` plus `/sys/module/*/taint` (unsigned, out-of-tree) | reported unsupported |
| listening_ports | psutil socket table | psutil socket table | psutil (may report `denied`) |
| dns | Tcpip interface NameServer values, hosts file | `/etc/resolv.conf`, `/etc/hosts` | `/etc/resolv.conf`, `/etc/hosts` |

Every inventory result uses the same envelope: `collector`, `collector_version`, `platform`,
`endpoint`, `collected_at`, `collection_status` (`collected`, `partial`, `unsupported`, `denied`
or `error`), `count`, `items`, `errors` and `provenance`.

`analyze detections` runs the declarative rules in `docs/DETECTION.md` over whatever the script collected.

`analyze <anything else>` compiles but has no capability. The platform backend flags it as
`unknown`, and the runtime policy denies it.

## IR 2.0

```json
{
  "version": "2.0",
  "case_id": "System_Audit_001",
  "target": "lab-pc",
  "platform": "AUTO",
  "required_capabilities": ["COLLECT_PROCESSES", "COLLECT_SYSTEM", "REPORT_HTML"],
  "operations": [
    {
      "id": "op-2",
      "type": "COLLECT",
      "target": "PROCESSES",
      "filters": [{"field": "status", "operator": "==", "value": "RUNNING"}],
      "capability": "COLLECT_PROCESSES",
      "output_schema": "jocky.process_list.v1",
      "platforms": ["LINUX", "MACOS", "WINDOWS"],
      "source": {"line": 5, "column": 5}
    }
  ]
}
```

2.0 only adds keys to 1.0, and the executor still accepts 1.0 IR.

## Platform backend

`compile_jocky(source, platform=...)` and `POST /api/jocky/compile {"platform": "linux"}` return a
`backend` plan. The platform is chosen in this order: the explicit request, then the script's
`platform` statement, then the compiling host. Each operation is `supported`, `unsupported`
(with the platforms that do support it) or `unknown`, so nothing is silently skipped.

## Error codes

Every diagnostic includes `code`, `message`, `line`, `column` and, where a close match exists,
a `hint` such as `Did you mean 'COLLECT'?`.

| Code | Meaning |
|---|---|
| JKY101 | Unterminated string literal |
| JKY102 | Unexpected character |
| JKY200 | Expected token not found |
| JKY201 | Unexpected trailing token after statement |
| JKY202 | CASE / investigation requires a quoted identifier |
| JKY203 | TARGET requires a quoted host name |
| JKY204 | VERIFY must be followed by INTEGRITY |
| JKY205 | Unknown command |
| JKY206 | Unknown COLLECT target |
| JKY207 | COLLECT FILES requires a quoted path |
| JKY208 | Invalid report format token |
| JKY209 | Unbalanced investigation block |
| JKY210 | Malformed WHERE clause |
| JKY211 | Invalid PLATFORM value |
| JKY301 | Missing CASE declaration |
| JKY302 | Duplicate CASE declaration |
| JKY303 | Missing TARGET declaration |
| JKY304 | Duplicate TARGET declaration |
| JKY305 | Empty identifier |
| JKY306 | Empty COLLECT FILES path |
| JKY307 | No COLLECT operation |
| JKY308 | Duplicate PLATFORM declaration |
| JKY310 | Invalid filter field |
| JKY311 | Invalid filter value |
| JKY320 | VERIFY INTEGRITY before any evidence collection |
| JKY330 | Unsupported report format |

## What the language deliberately cannot express

There is no way to run a shell command, write files outside the evidence store, inject into
processes, load drivers, persist, or escalate privileges. Unknown words fail compilation, and
anything the compiler lets through is checked again by the runtime policy before a collector runs.
