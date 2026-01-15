# IDA Pro Analysis Guide: Detecting Backdoor Patterns

## Step 1: Loading the Binary in IDA Pro

1. Open IDA Pro
2. **File → Open** or drag `simple_backdoor.exe` into IDA
3. Choose the appropriate processor (PE x86/x64)
4. Wait for auto-analysis to complete

## Step 2: Initial Reconnaissance

### A. Check the Imports (Import Address Table)
- **View → Open Subviews → Imports** (or press `Ctrl+I`)

**Suspicious imports to look for:**
```
ws2_32.dll (Winsock functions):
├── WSAStartup        ← Network initialization
├── socket            ← Socket creation
├── connect           ← Outbound connection (RED FLAG!)
├── send/recv         ← Data transmission
├── closesocket       ← Cleanup
└── WSACleanup        ← Cleanup

kernel32.dll:
├── _popen            ← Execute commands (RED FLAG!)
├── CreateProcess     ← Process creation
├── Sleep             ← Delays/anti-analysis
└── GetModuleFileName ← Self-reference

advapi32.dll (if present):
├── RegCreateKeyEx    ← Registry persistence (RED FLAG!)
└── RegSetValueEx     ← Registry modification
```

## Step 3: String Analysis (Critical for Detection!)

### Method 1: Using IDA's String Window
1. **View → Open Subviews → Strings** (or press `Shift+F12`)
2. Look for:
   - IP addresses (e.g., "127.0.0.1", "0.0.0.0")
   - Port numbers
   - Command-related strings: "cmd.exe", "exit", "shell"
   - URLs or domains
   - Error messages revealing functionality

**In our sample, you'll find:**
```
"Initializing Winsock"
"Socket created"
"Connecting to %s:%d"
"Received command"
"exit"  ← Command keyword
```

### Method 2: XOR-Encoded Strings Detection
- Look for XOR operations near string usage
- Check for loops with `xor` instruction followed by string references
- Our sample uses: `encoded[i] ^= key;`

## Step 4: Function Analysis

### Finding the Main Entry Point
1. Go to the entry point: **Jump → Jump to Entry Point** (or press `G` and type "start")
2. Follow the flow to `main()` function

### Identifying Suspicious Functions
1. **View → Open Subviews → Functions** (or press `Shift+F3`)
2. Look for:
   - Functions calling `socket()` + `connect()` combination
   - Functions with names like: `establish_connection`, `reverse_shell`, `cmd_handler`
   - Functions calling `_popen`, `WinExec`, `CreateProcess`

### Analyze Key Function: `establish_connection()`
**How to find it:**
1. Press `Ctrl+F` to search for string "Initializing Winsock"
2. Double-click the string
3. Press `X` (cross-references) to see where it's used
4. Follow to the function

**What to look for in IDA disassembly:**
```assembly
; Pattern 1: Winsock initialization
push    offset unk_...    ; lpWSAData
push    202h              ; 0x202 = MAKEWORD(2,2)
call    WSAStartup

; Pattern 2: Socket creation
push    0                 ; protocol
push    1                 ; SOCK_STREAM (TCP)
push    2                 ; AF_INET
call    socket

; Pattern 3: Connect to remote host (MAJOR RED FLAG!)
push    10h              ; namelen
push    esi              ; sockaddr structure
push    edi              ; socket
call    connect

; Pattern 4: Command loop
.loop:
call    recv             ; Receive data
call    _popen           ; Execute command (DANGER!)
call    send             ; Send results back
jmp     .loop
```

## Step 5: Graph View Analysis (Visual Detection)

### Accessing Graph View
1. Select a function (e.g., `establish_connection`)
2. Press **SPACEBAR** to toggle between Text View and Graph View
3. Or use **View → Graph Overview**

### What to Look for in Graph View:

#### 1. **Network Communication Pattern**
```
┌─────────────────┐
│  WSAStartup()   │
└────────┬────────┘
         │
┌────────▼────────┐
│    socket()     │
└────────┬────────┘
         │
┌────────▼────────┐
│   connect()     │ ← RED FLAG! Outbound connection
└────────┬────────┘
         │
    ┌────▼────┐
    │ Success?│
    └─┬─────┬─┘
  Yes │     │ No
      │     └──→ (Exit)
      │
┌─────▼──────┐
│  Loop recv │ ← Command loop
│   & send   │
└─────┬──────┘
      │
      └──→ (Repeat)
```

#### 2. **XOR Decoding Pattern**
```
┌──────────────┐
│ Start Loop   │
└──────┬───────┘
       │
┌──────▼───────┐
│ encoded[i]   │
│    ^= key    │ ← XOR obfuscation
└──────┬───────┘
       │
┌──────▼───────┐
│ i++; i < len?│
└──┬─────────┬─┘
   │ Yes     │ No
   └────┐    └──→ (Exit)
        └──→ (Loop back)
```

#### 3. **Command Execution Pattern**
```
┌──────────────┐
│   recv()     │ ← Receive command
└──────┬───────┘
       │
┌──────▼───────┐
│ Check "exit" │
└──┬─────────┬─┘
   │ Match   │ No match
   │         │
   │    ┌────▼────┐
   │    │ _popen()│ ← Execute command (RED FLAG!)
   │    └────┬────┘
   │         │
   │    ┌────▼────┐
   │    │  send() │ ← Send results
   │    └────┬────┘
   │         │
   └────→(Exit)  └─→ (Loop back to recv)
```

## Step 6: Cross-Reference Analysis

### Finding All References to Suspicious Functions
1. Navigate to `_popen` import
2. Press `X` to view cross-references
3. See all locations where commands are executed

### Analyzing Data Flow
1. Right-click on a variable → **Jump to Cross Reference**
2. Track how data flows from `recv()` → `_popen()` → `send()`

## Step 7: Behavioral Indicators (Detection Summary)

### 🚩 RED FLAGS Checklist

| Indicator | Location | Severity |
|-----------|----------|----------|
| `socket()` + `connect()` combination | establish_connection() | HIGH |
| `_popen()` with user-controlled input | Command loop | CRITICAL |
| XOR operations on strings | decode_string() | MEDIUM |
| Hardcoded IP/Port | main() | HIGH |
| Infinite recv/send loop | establish_connection() | HIGH |
| Registry persistence attempts | install_persistence() | CRITICAL |

## Step 8: Creating Visual Documentation for Students

### Generate Flow Charts
1. **View → Generate Flow Chart**
2. Export as PDF for student handouts

### Creating Annotations
1. Select instruction
2. Press `:` or `Ins` to add comment
3. Press `;` to add repeatable comment
4. Use `Shift+;` for anterior lines

### Highlighting Suspicious Code
1. Select instruction/function
2. **Edit → Other → Manual instruction...**
3. Change background color

## Step 9: Automated Detection with IDA Python (Advanced)

### Example IDA Python Script
```python
import idaapi
import idautils

def find_backdoor_patterns():
    # Find all calls to 'connect'
    connect_addr = idaapi.get_name_ea(0, "connect")
    if connect_addr != idaapi.BADADDR:
        print("[!] Found 'connect' function - possible backdoor!")

        for xref in idautils.XrefsTo(connect_addr):
            print(f"  └─ Called from: {hex(xref.frm)}")

    # Find command execution
    popen_addr = idaapi.get_name_ea(0, "_popen")
    if popen_addr != idaapi.BADADDR:
        print("[!] Found '_popen' - possible command execution!")

        for xref in idautils.XrefsTo(popen_addr):
            print(f"  └─ Called from: {hex(xref.frm)}")

find_backdoor_patterns()
```

## Step 10: Student Exercise Questions

### Level 1: Basic
1. What network functions are imported by this binary?
2. Find the hardcoded IP address and port number.
3. How many suspicious strings can you identify?

### Level 2: Intermediate
4. Trace the data flow from `recv()` to `_popen()`.
5. What obfuscation technique is used for strings?
6. Identify the command execution loop in graph view.

### Level 3: Advanced
7. Write an IDA Python script to detect similar backdoors.
8. How would you modify the binary to evade this detection?
9. Create YARA rules based on the patterns found.

## Additional Resources

- **IDA Pro Shortcuts**: Press `?` in IDA for help
- **Hex-Rays Decompiler**: Press `F5` for pseudocode (if available)
- **Function Graph**: `Space` to toggle views
- **Cross-references**: `X` to find usages

## Summary: Quick Detection Workflow

1. **Imports** (`Ctrl+I`) → Look for networking + execution functions
2. **Strings** (`Shift+F12`) → Find IPs, commands, suspicious text
3. **Functions** (`Shift+F3`) → Identify network communication functions
4. **Graph View** (Spacebar) → Visualize control flow
5. **Cross-refs** (`X`) → Track data flow and function usage

---

**Remember**: Always analyze malware in isolated environments!
