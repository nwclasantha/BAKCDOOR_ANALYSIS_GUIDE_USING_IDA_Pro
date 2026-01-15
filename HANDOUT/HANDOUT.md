# Student Handout: Backdoor Detection with IDA Pro

**Course**: MSc Cybersecurity - Malware Analysis Lab
**Topic**: Static Analysis of Backdoor Malware
**Tool**: IDA Pro Disassembler

---

## Learning Objectives

By the end of this lab, you will be able to:
- ✓ Identify backdoor patterns in compiled binaries
- ✓ Use IDA Pro's visual tools for malware analysis
- ✓ Detect obfuscation techniques
- ✓ Create indicators of compromise (IOCs)
- ✓ Document malware behavior

---

## Part 1: Pre-Lab Preparation

### Files You Need:
- `simple_backdoor.exe` (or `simple_backdoor_debug.exe`)
- IDA Pro (Free or Commercial version)
- This handout

### Safety First! ⚠️
- Work only in the isolated lab network
- Do NOT connect to the internet during analysis
- Do NOT run the malware outside the VM
- Do NOT copy the malware to personal devices

---

## Part 2: IDA Pro Quick Start

### Opening the Binary:
1. Launch IDA Pro
2. File → Open → Select `simple_backdoor_debug.exe`
3. Choose "PE" for Portable Executable
4. Wait for auto-analysis (watch progress bar)

### Essential Views:

| View | Shortcut | Purpose |
|------|----------|---------|
| Imports | `Ctrl+I` | Shows external functions used |
| Strings | `Shift+F12` | Shows text strings in binary |
| Functions | `Shift+F3` | Lists all functions |
| Graph View | `Spacebar` | Visual flow chart of code |
| Hex View | `F2` | Raw bytes |

---

## Part 3: Detection Methodology

### Step 1: Import Analysis (10 minutes)

**Task**: Press `Ctrl+I` to open Imports window

**Look for these suspicious combinations:**

```
NETWORKING FUNCTIONS:
☐ WSAStartup     - Initialize network library
☐ socket         - Create network socket
☐ connect        - Connect to remote host  ← RED FLAG!
☐ bind/listen    - Accept connections
☐ send/recv      - Send/receive data

EXECUTION FUNCTIONS:
☐ system         - Execute shell commands
☐ WinExec        - Execute programs
☐ CreateProcess  - Create new process
☐ _popen         - Open pipe to command  ← RED FLAG!
☐ ShellExecute   - Execute files

PERSISTENCE FUNCTIONS:
☐ RegCreateKey   - Create registry key  ← RED FLAG!
☐ RegSetValue    - Modify registry
☐ CopyFile       - Copy files
```

**Question 1**: Which dangerous functions are imported by this binary?

_Your answer:_ ___________________________________

**Question 2**: What does the combination of `connect` + `_popen` indicate?

_Your answer:_ ___________________________________

---

### Step 2: String Analysis (10 minutes)

**Task**: Press `Shift+F12` to open Strings window

**Look for:**
- IP addresses (e.g., 127.0.0.1, 192.168.x.x)
- Port numbers
- URLs or domain names
- Command keywords ("cmd", "shell", "exit", "exec")
- File paths
- Error messages revealing functionality

**Fill in the table:**

| String Found | Location (Address) | Suspicion Level (Low/Med/High) |
|--------------|-------------------|-------------------------------|
| | | |
| | | |
| | | |
| | | |

**Question 3**: What IP address and port does this backdoor target?

IP: ____________  Port: ____________

---

### Step 3: Function Analysis (15 minutes)

**Task**: Press `Shift+F3` to see all functions

**Identify these patterns:**

Suspicious Function Names:
- Contains words: "connect", "shell", "cmd", "exec", "backdoor"
- Contains words: "install", "persist", "hide", "inject"
- Obfuscation related: "decode", "decrypt", "unpack"

**List 5 most suspicious functions:**

1. _________________________________
2. _________________________________
3. _________________________________
4. _________________________________
5. _________________________________

**Question 4**: What do you think `establish_connection` function does?

_Your answer:_ ___________________________________

---

### Step 4: Graph View Analysis (20 minutes)

**Task**: Double-click on `establish_connection` function, press `Spacebar`

**Understand the flow chart symbols:**

```
┌────────────┐
│ Basic Block│  ← Sequential instructions (no branches)
└──────┬─────┘
       │  ← Unconditional flow
       ▼

┌────────────┐
│ Condition  │
└──┬──────┬──┘
   │ Yes  │ No  ← Conditional branch (if/else)
   ▼      ▼

┌─────┐  ┌─────┐
│Path1│  │Path2│
└──┬──┘  └──┬──┘
   │        │
   └────┬───┘
        │  ← Paths merge
        ▼
```

**Question 5**: Draw the simplified flow of `establish_connection`:

```
START
  │
  ▼
[Your diagram here]
  │
  ▼
END
```

**Look for these patterns in the graph:**

☐ **Loop (back edge)**: Arrow pointing upward = repeated execution
☐ **Network initialization**: WSAStartup → socket → connect
☐ **Command loop**: recv → check → execute → send → repeat
☐ **XOR operations**: Indicates string obfuscation

---

### Step 5: Cross-Reference Analysis (15 minutes)

**Task**: Find all places where `_popen` is called

**Steps:**
1. Navigate to `_popen` in Imports window
2. Press `X` to see cross-references
3. Double-click each reference to see context

**Question 6**: How many times is `_popen` called?

_Your answer:_ ___________________________________

**Question 7**: What data is passed to `_popen` (what gets executed)?

_Your answer:_ ___________________________________

---

## Part 4: Behavioral Analysis

### Command Execution Flow

**Trace the data flow** from network input to command execution:

```
1. recv(socket, buffer, size) → receives data from network
                │
                ▼
2. buffer contains: _________________________
                │
                ▼
3. Validation check? [YES / NO] (circle one)
                │
                ▼
4. _popen(buffer) → executes buffer as command
                │
                ▼
5. send(socket, result) → sends output back
```

**Question 8**: Is there input validation between recv() and _popen()?
☐ Yes  ☐ No

**Question 9**: Why is this dangerous?

_Your answer:_ ___________________________________

---

### Obfuscation Detection

**Find the `decode_string` function:**

**Question 10**: What obfuscation technique is used?
☐ XOR encryption
☐ Base64 encoding
☐ ROT13
☐ AES encryption

**Question 11**: What is the XOR key value?

_Your answer:_ ___________________________________

**Why obfuscate?**
- Hide malicious strings from simple analysis
- Evade signature-based detection
- Make reverse engineering harder

---

## Part 5: Creating IOCs (Indicators of Compromise)

### Network IOCs:

| Type | Value | Confidence |
|------|-------|-----------|
| IP Address | | |
| Port | | |
| Protocol | TCP / UDP (circle one) | |

### File IOCs:

| Property | Value |
|----------|-------|
| File Name | simple_backdoor.exe |
| File Size | |
| MD5 Hash | (use: `md5sum simple_backdoor.exe`) |
| SHA256 | (use: `sha256sum simple_backdoor.exe`) |

### Behavioral IOCs:

☐ Establishes outbound network connection
☐ Executes arbitrary commands
☐ No user interaction required
☐ String obfuscation present
☐ Persistence mechanism (if found)

---

## Part 6: Detection Report

**Write a 1-paragraph summary of this malware:**

_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________

**Malware Classification:**
☐ Trojan  ☐ Worm  ☐ Virus  ☐ Rootkit  ☐ Backdoor  ☐ Ransomware

**Primary Functionality:**
☐ Data theft  ☐ Remote access  ☐ Encryption  ☐ DDoS  ☐ Other: ______

**Severity Level:**
☐ Low  ☐ Medium  ☐ High  ☐ Critical

---

## Part 7: YARA Rule Creation (Advanced)

**YARA** is a pattern-matching tool for malware detection.

**Create a YARA rule for this backdoor:**

```yara
rule Educational_Backdoor
{
    meta:
        author = "Your Name"
        description = "Detects simple backdoor pattern"
        date = "2026-01-15"

    strings:
        // Add strings you found (at least 3)
        $str1 = "_______________________________"
        $str2 = "_______________________________"
        $str3 = "_______________________________"

        // Add function names or patterns
        $func1 = "_______________________________"

    condition:
        // Define detection logic
        // Example: (2 of ($str*)) and $func1

        ____________________________________
}
```

**Test your YARA rule:**
```bash
yara your_rule.yar simple_backdoor.exe
```

---

## Part 8: Remediation Recommendations

**If you found this malware on a system, what would you do?**

**Immediate Actions:**
☐ 1. _______________________________________________
☐ 2. _______________________________________________
☐ 3. _______________________________________________

**Investigation Steps:**
☐ 1. Check network logs for connection to malicious IP
☐ 2. _______________________________________________
☐ 3. _______________________________________________

**Prevention Measures:**
☐ 1. _______________________________________________
☐ 2. _______________________________________________
☐ 3. _______________________________________________

---

## Part 9: Advanced Challenges (Optional)

### Challenge 1: Patch the Backdoor
**Task**: Use IDA Pro's hex editing to change the target IP to 0.0.0.0
**Hint**: Edit → Patch program → Change byte

### Challenge 2: Find Hidden Functionality
**Task**: Analyze the `install_persistence` function
**Question**: What would it do if it were active?

### Challenge 3: Dynamic Analysis
**Task**: Run the backdoor in a debugger (x64dbg)
**Set breakpoint at**: `_popen` call
**Observe**: What command is being executed in real-time?

### Challenge 4: Write Snort Rule
**Task**: Create a network IDS rule to detect this backdoor's traffic

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (
    msg:"Possible Backdoor Connection";
    content:"|_____|";
    sid:1000001;
    rev:1;
)
```

---

## Part 10: Assessment Questions

### Multiple Choice:

**1. What is the primary indicator that this is a backdoor?**
- A) It uses the Windows API
- B) It combines network connectivity with command execution
- C) It has obfuscated strings
- D) It's written in C

**2. The `connect()` function indicates:**
- A) The malware accepts incoming connections (bind shell)
- B) The malware initiates outbound connections (reverse shell)
- C) The malware creates a botnet
- D) Normal network activity

**3. Why would an attacker obfuscate the target IP address?**
- A) To make the code run faster
- B) To evade signature-based detection
- C) To compress the binary
- D) To add encryption

### Short Answer:

**4. Explain the difference between static and dynamic malware analysis.**

_Your answer:_ ___________________________________
________________________________________________
________________________________________________

**5. How could this backdoor be modified to evade the detection methods you used?**

_Your answer:_ ___________________________________
________________________________________________
________________________________________________

---

## Checklist: Have You Completed?

☐ Identified all suspicious imports
☐ Found the hardcoded IP and port
☐ Analyzed the graph view of main malicious function
☐ Traced data flow from recv() to _popen()
☐ Detected the obfuscation technique
☐ Created a list of IOCs
☐ Written a detection report
☐ Created a YARA rule (if time permits)
☐ Recommended remediation steps

---

## Additional Resources

**IDA Pro Documentation:**
- Official guide: https://hex-rays.com/documentation/

**Malware Analysis Training:**
- Malware Unicorn: https://malwareunicorn.org/
- Practical Malware Analysis (book)

**Practice Samples:**
- Crackmes: https://crackmes.one/
- MalwareBazaar: https://bazaar.abuse.ch/ (advanced)

**YARA Resources:**
- YARA documentation: https://yara.readthedocs.io/
- YARA rule examples: https://github.com/Yara-Rules/rules

---

## Lab Report Submission

**Submit the following:**
1. Completed handout (this document)
2. Screenshots of IDA Pro analysis showing:
   - Imports window with annotations
   - Strings window highlighting IOCs
   - Graph view of `establish_connection`
3. Your YARA rule (saved as `[YourName]_backdoor.yar`)
4. 2-3 page written report including:
   - Executive summary
   - Technical analysis
   - IOCs
   - Remediation recommendations

**Due Date**: _________________

**Grading Rubric:**
- Import/String Analysis: 20%
- Function & Graph Analysis: 30%
- IOC Creation: 20%
- YARA Rule: 15%
- Written Report: 15%

---

**Remember**: Malware analysis is a critical cybersecurity skill. Practice in safe, controlled environments only!

**Questions?** Ask your instructor or refer to the comprehensive guides:
- `IDA_ANALYSIS_GUIDE.md`
- `VISUAL_DIAGRAM_GUIDE.md`
- `QUICK_START.md`

---

**Good luck with your analysis!** 🔍🛡️
