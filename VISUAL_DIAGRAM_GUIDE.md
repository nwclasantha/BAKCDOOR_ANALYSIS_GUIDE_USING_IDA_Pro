# IDA Pro Visual Diagram Guide for Students

## Part 1: Understanding IDA Pro's Visual Views

### 1. Graph View (Flow Chart View)

The **Graph View** is the most important visual tool for understanding program behavior.

#### How to Access:
- Load binary in IDA Pro
- Navigate to any function
- Press **SPACEBAR** to switch between Text View ↔ Graph View

#### What You See:

```
┌──────────────────────────────────────┐
│        BASIC BLOCK                   │  ← A block of sequential instructions
│  push    ebp                         │
│  mov     ebp, esp                    │
│  sub     esp, 40h                    │
│  call    WSAStartup                  │
└──────────────┬───────────────────────┘
               │
               │ (Unconditional flow)
               ▼
┌──────────────────────────────────────┐
│  test    eax, eax                    │  ← Condition check
│  jz      short loc_success           │
└──────┬───────────────────────────┬───┘
       │                           │
   Fail│                      Pass │
       ▼                           ▼
┌─────────────┐           ┌─────────────┐
│ Error Path  │           │ Success Path│
│ return -1   │           │ continue... │
└─────────────┘           └─────────────┘
```

### 2. Proximity View

Shows how functions are related and call each other.

**Access**: View → Open Subviews → Proximity Browser

```
                  main()
                    │
        ┌───────────┼───────────┐
        │           │           │
        ▼           ▼           ▼
decode_string() check_updates() establish_connection()
                                        │
                            ┌───────────┼───────────┐
                            ▼           ▼           ▼
                        socket()    connect()   _popen()
                                                   │
                                                   └─→ MALICIOUS!
```

### 3. Function Call Graph

**Access**: View → Open Subviews → Function Calls

Shows ALL function relationships in the entire binary.

## Part 2: Backdoor Detection - Visual Patterns

### Pattern 1: Network Communication Flow

#### Normal Program:
```
┌────────┐
│ main() │
└───┬────┘
    │
    ▼
┌───────────┐
│ Business  │
│   Logic   │
└───────────┘
```

#### Backdoor Program:
```
┌────────┐
│ main() │
└───┬────┘
    │
    ├─→ Decoy Function (looks innocent)
    │
    └─→ establish_connection() ← SUSPICIOUS!
              │
              ├─→ WSAStartup()
              ├─→ socket()
              ├─→ connect() ← RED FLAG!
              │        │
              │        └─→ Remote IP/Port
              │
              └─→ Command Loop
                     │
                     ├─→ recv() ← Receive commands
                     ├─→ _popen() ← Execute! DANGER!
                     └─→ send() ← Send results back
```

### Pattern 2: String Obfuscation Detection

#### In Graph View, look for this pattern:

```
┌─────────────────────────┐
│ Load encrypted string   │
│ lea  eax, [ebp+var_50] │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ XOR Decode Loop         │  ← OBFUSCATION!
│ ┌──────────────────┐    │
│ │ mov  al, [esi]   │    │
│ │ xor  al, 55h     │ ←──┼─ Key 0x55
│ │ mov  [esi], al   │    │
│ │ inc  esi         │    │
│ │ loop short loc_X │    │
│ └──────────────────┘    │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Use decoded string      │
│ push eax ; IP address   │
│ call connect            │
└─────────────────────────┘
```

### Pattern 3: Command Execution Loop

#### Visual identification in Graph View:

```
                    START
                      │
                      ▼
        ┌──────────────────────────┐
        │   Initialize Socket      │
        │   call WSAStartup        │
        │   call socket            │
        │   call connect           │
        └──────────┬───────────────┘
                   │
                   ▼
        ┌──────────────────────────┐
  ┌────→│   recv() command buffer  │←────┐
  │     └──────────┬───────────────┘     │
  │                │                      │
  │                ▼                      │
  │     ┌──────────────────────────┐     │
  │     │  Compare: is "exit"?     │     │
  │     └──────┬──────────────┬────┘     │
  │            │              │           │
  │         Yes│              │No         │
  │            │              ▼           │
  │            │   ┌──────────────────┐  │
  │            │   │  call _popen()   │  │ ← DANGER!
  │            │   │  Execute command │  │
  │            │   └────────┬─────────┘  │
  │            │            │             │
  │            │            ▼             │
  │            │   ┌──────────────────┐  │
  │            │   │  call send()     │  │
  │            │   │  Send output back│  │
  │            │   └────────┬─────────┘  │
  │            │            │             │
  │            │            └─────────────┘
  │            ▼                   (Loop back)
  │     ┌──────────────┐
  └─────│  Clean up    │
        │  closesocket │
        │  WSACleanup  │
        └──────────────┘
              │
              ▼
            EXIT
```

**Key Features to Point Out to Students:**
- 🔴 The infinite loop (`recv → execute → send → repeat`)
- 🔴 Direct path from network input (`recv`) to execution (`_popen`)
- 🔴 No input validation between recv and _popen
- 🔴 Back-edge in the graph (arrow going upward = loop)

## Part 3: Step-by-Step Visual Analysis Demo

### Demo Script for Students:

#### Step 1: Load Binary
1. Open IDA Pro
2. File → Open → `simple_backdoor.exe`
3. Wait for auto-analysis (progress bar at bottom)

#### Step 2: First Visual - Import Graph
1. View → Open Subviews → Imports (Ctrl+I)
2. **Point out these imports on screen:**

```
ws2_32.dll
  ├─ WSAStartup     ← "Students, this means network activity"
  ├─ socket         ← "Creating a network socket"
  ├─ connect        ← "RED FLAG: Outbound connection!"
  ├─ recv           ← "Receiving data from network"
  └─ send           ← "Sending data to network"

kernel32.dll
  └─ _popen         ← "CRITICAL: This executes commands!"
```

**Question for students**: "What does it mean when a program has BOTH network functions AND command execution?"

#### Step 3: Function List Visual
1. View → Open Subviews → Functions (Shift+F3)
2. Sort by name
3. **Highlight these functions:**

```
Functions Window:
┌────────────────────────────────────────────┐
│ ☐ check_system_updates                    │ ← Decoy (innocent)
│ ☐ decode_string                            │ ← Obfuscation!
│ ☐ establish_connection                     │ ← SUSPICIOUS NAME!
│ ☐ install_persistence                      │ ← VERY SUSPICIOUS!
│ ☐ main                                     │ ← Entry point
└────────────────────────────────────────────┘
```

**Ask students**: "Based on function names alone, which look suspicious?"

#### Step 4: Graph View of Malicious Function

1. Double-click `establish_connection`
2. Press SPACEBAR for Graph View
3. **Walk through the flow:**

**Point to each block on screen:**

```
Block 1 (Entry):
┌─────────────────────┐
│ function prologue   │ ← "This is function setup"
│ push ebp            │
│ mov ebp, esp        │
└──────────┬──────────┘

Block 2 (Winsock Init):
┌─────────────────────┐
│ call WSAStartup     │ ← "Initialize networking"
│ test eax, eax       │
└──────┬──────────────┘
       │
    Success?
       │
Block 3 (Socket Create):
┌─────────────────────┐
│ push 0              │
│ push 1              │ ← SOCK_STREAM (TCP)
│ push 2              │ ← AF_INET
│ call socket         │ ← "Create socket"
└──────┬──────────────┘

Block 4 (Connect - KEY BLOCK!):
┌─────────────────────┐
│ mov [var_IP], ...   │ ← "See the IP address here!"
│ mov [var_port], ... │ ← "And the port number!"
│ call connect        │ ← "Connecting to attacker!"
└──────┬──────────────┘
       │
  Connected?
       │
Block 5 (Command Loop - MAIN MALICIOUS LOGIC):
    ┌────────────────┐
    │ call recv      │ ← "Wait for command from attacker"
    └────┬───────────┘
         │
         ▼
    ┌────────────────┐
    │ cmp buffer,"exit"│ ← "Check if exit command"
    └────┬─────────┬─┘
      Yes│         │No
         │         ▼
         │    ┌────────────────┐
         │    │ call _popen    │ ← "EXECUTE THE COMMAND!"
         │    └────┬───────────┘    ← "Point and say: THIS IS WHERE THE BACKDOOR EXECUTES ATTACKER'S COMMANDS!"
         │         │
         │         ▼
         │    ┌────────────────┐
         │    │ call send      │ ← "Send results back"
         │    └────┬───────────┘
         │         │
         └─────────┴─→ (loop back or exit)
```

**Key Teaching Points:**
- "See this arrow going UP? That's a loop - it keeps waiting for commands"
- "Notice: NO validation between recv and _popen - anything received gets executed!"
- "This is a classic reverse shell pattern"

#### Step 5: Cross-Reference Analysis

1. Right-click on `_popen` in the graph
2. Select "Jump to xref to operand" or press `X`

**Show students the cross-reference window:**

```
Cross-references to _popen:
┌─────────────────────────────────────────────────┐
│ establish_connection+142  call _popen          │ ← "Only one place calls this"
└─────────────────────────────────────────────────┘
```

**Exercise**: "Now students, press X on `connect` and see where it's called from."

#### Step 6: String Analysis Visual

1. View → Strings (Shift+F12)
2. Sort by clicking "String" column

**Show students:**

```
Strings Window:
┌──────────────────────────────────────────────────────┐
│ Address   │ String                                   │
├───────────┼──────────────────────────────────────────┤
│ 00403000  │ "Initializing Winsock..."                │
│ 00403020  │ "Socket created"                         │
│ 00403040  │ "Connecting to %s:%d"                    │ ← "Format string - suspicious!"
│ 00403060  │ "Received command: %s"                   │ ← RED FLAG!
│ 00403080  │ "exit"                                   │ ← Command keyword
└───────────┴──────────────────────────────────────────┘
```

**Double-click on any string → Press X** to see where it's used.

## Part 4: Color Coding for Visual Teaching

### Suggested Color Scheme in IDA:

**To change colors:**
1. Right-click on instruction/block
2. "Set color" or Edit → Other → Set block color

**Color Legend:**
- 🟥 **RED** = Dangerous functions (_popen, system, WinExec, CreateProcess)
- 🟧 **ORANGE** = Network functions (connect, send, recv)
- 🟨 **YELLOW** = Obfuscation (XOR, decode loops)
- 🟦 **BLUE** = Legitimate functionality
- 🟪 **PURPLE** = Persistence mechanisms (Registry, Startup folder)

### Example Annotated Graph:

```
┌─────────────────────────┐
│   [BLUE]                │
│   check_system_updates  │  ← Decoy function
│   printf("Checking...")  │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   [ORANGE]              │
│   call WSAStartup       │  ← Network initialization
│   call socket           │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   [ORANGE/RED]          │
│   call connect          │  ← Outbound connection
│   push IP_ADDRESS       │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   [RED] ⚠️              │
│   call recv             │
│   call _popen           │  ← COMMAND EXECUTION!
│   call send             │
└─────────────────────────┘
```

## Part 5: Creating Student Handouts from IDA

### Exporting Graphs:

#### Method 1: Screenshot
1. Navigate to function in Graph View
2. Fit to window: Press `-` (minus key)
3. **Edit → Export → Save image as PNG**

#### Method 2: Generate Flowchart
1. **View → Generate Flowchart**
2. Choose GDL format
3. Open in other tools (yEd, Graphviz)

#### Method 3: IDA's Built-in Export
1. File → Produce file → Create ASM file
2. File → Produce file → Create HTML file (includes colors!)

### PDF Report Generation:

Create a comprehensive PDF with:
```
1. Cover page with binary info
2. Function list with annotations
3. Graph views of key functions:
   - main()
   - establish_connection()
   - decode_string()
4. Import/Export tables
5. String list with suspicious items highlighted
6. Cross-reference analysis
7. Detection summary
```

## Part 6: Interactive Student Exercises

### Exercise 1: "Find the IP and Port"
**Task**: Using only IDA's visual tools, find the hardcoded IP and port.

**Hints:**
1. Go to strings window (Shift+F12)
2. Look for `connect` function in imports
3. Press X on `connect` to see parameters
4. Look for `push` instructions before the call

### Exercise 2: "Trace the Command Flow"
**Task**: Create a diagram showing data flow from `recv()` to `_popen()`.

**Method:**
1. Find `recv` call
2. Note the buffer variable
3. Follow that variable using cross-references
4. See where it's passed to `_popen`

### Exercise 3: "Identify All Malicious Functions"
**Task**: Create a list of functions and rate their suspicion level.

**Use:**
- Proximity view for relationships
- Function calls view for connections
- Graph view for behavior

## Part 7: Detection Checklist (Visual)

### Print this checklist for students:

```
┌─────────────────────────────────────────────────────────┐
│ IDA Pro Malware Detection Checklist                    │
├─────────────────────────────────────────────────────────┤
│ □ Check Imports (Ctrl+I)                               │
│   □ Networking: socket, connect, send, recv            │
│   □ Execution: system, _popen, CreateProcess, WinExec │
│   □ Persistence: RegCreateKey, CopyFile               │
│                                                         │
│ □ String Analysis (Shift+F12)                          │
│   □ IP addresses and URLs                              │
│   □ Suspicious commands (cmd, powershell, bash)       │
│   □ Obvious malicious keywords                         │
│                                                         │
│ □ Function Analysis (Shift+F3)                         │
│   □ Suspicious function names                          │
│   □ Functions with network + execution combo           │
│                                                         │
│ □ Graph View Analysis (Space)                          │
│   □ Look for loops with recv/send                      │
│   □ Find XOR/decode patterns                           │
│   □ Identify command execution paths                   │
│                                                         │
│ □ Cross-Reference Analysis (X)                         │
│   □ Trace dangerous function calls                     │
│   □ Follow data flow                                   │
│                                                         │
│ □ Behavioral Patterns                                  │
│   □ Network init → connect → loop → execute           │
│   □ String obfuscation (XOR, base64)                   │
│   □ Anti-debugging (IsDebuggerPresent, timing)        │
└─────────────────────────────────────────────────────────┘
```

## Summary: Teaching Flow

### Recommended 2-Hour Lab Session:

**00:00-00:15** - Introduction to IDA Pro interface
**00:15-00:30** - Imports and Strings analysis
**00:30-00:45** - Function list and names
**00:45-01:00** - Text view → Graph view
**01:00-01:20** - Deep dive into malicious function
**01:20-01:40** - Cross-reference analysis
**01:40-02:00** - Student hands-on detection exercise

---

**Pro Tips for Teaching:**
- Use a projector for live demonstration
- Annotate graphs during presentation (colors, comments)
- Have students follow along on their own systems
- Provide the compiled binary before class
- Keep a "clean" IDA database and a "fully annotated" one for comparison
