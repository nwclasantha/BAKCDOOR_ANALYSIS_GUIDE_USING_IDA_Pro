# Quick Start Guide - Educational Backdoor Analysis

## What You Have Now

I've created a complete educational backdoor analysis package for your MSc students:

### 📁 Files Created:

1. **simple_backdoor.c** - The source code of the educational backdoor
2. **compile.bat** - Windows batch file to compile the backdoor
3. **IDA_ANALYSIS_GUIDE.md** - Complete guide for detecting malware with IDA Pro
4. **VISUAL_DIAGRAM_GUIDE.md** - Visual/diagrammatic analysis guide for IDA Pro
5. **COMPILE_INSTRUCTIONS.md** - Manual compilation instructions
6. **QUICK_START.md** - This file!

## Step-by-Step Instructions

### Step 1: Compile the Backdoor

**Option A: Easy Way (Recommended)**
1. Double-click `compile.bat`
2. Wait for compilation to finish
3. You should see 3 .exe files created

**Option B: Manual Compilation**
Open Command Prompt in this directory and run:
```bash
gcc simple_backdoor.c -o simple_backdoor.exe -lws2_32
```

### Step 2: Verify Compilation

Check that you have these files:
- `simple_backdoor.exe` (standard version)
- `simple_backdoor_debug.exe` (with debug symbols)
- `simple_backdoor_release.exe` (optimized and stripped)

### Step 3: Open in IDA Pro

1. Launch IDA Pro from: `D:\Forensics\`
2. **File → Open**
3. Select `simple_backdoor_debug.exe` (easiest to analyze)
4. Click "Yes" for auto-analysis
5. Wait for analysis to complete

### Step 4: Follow the Analysis Guide

Open **IDA_ANALYSIS_GUIDE.md** and follow these sections in order:
1. Check Imports (`Ctrl+I`) - Find network and execution functions
2. String Analysis (`Shift+F12`) - Find suspicious strings
3. Function Analysis - Identify malicious functions
4. Graph View Analysis (`Spacebar`) - Visualize the backdoor behavior

### Step 5: Use the Visual Guide for Teaching

Open **VISUAL_DIAGRAM_GUIDE.md** for:
- How to present IDA Pro graphs to students
- Color-coding suggestions
- Step-by-step demo script
- Student exercises and handouts

## What the Backdoor Does (Technical Summary)

This educational sample demonstrates a **reverse shell backdoor**:

1. **Obfuscation**: XOR-encodes the target IP address
2. **Network Connection**: Connects to 127.0.0.1:4444 (localhost for safety)
3. **Command Reception**: Waits for commands from the "attacker"
4. **Command Execution**: Runs commands using `_popen()`
5. **Result Transmission**: Sends output back to attacker

## Detection Points (What Students Should Find)

Students should detect these RED FLAGS:

### 🚩 In IDA Pro Imports Window:
- `WSAStartup`, `socket`, `connect` (networking)
- `_popen` (command execution) ← **CRITICAL**
- Combination of networking + execution = backdoor!

### 🚩 In Strings Window:
- "Connecting to %s:%d"
- "Received command"
- "exit" command keyword

### 🚩 In Graph View:
- Loop structure: `recv → execute → send → repeat`
- XOR decoding loop (obfuscation)
- Direct data flow from network to execution

### 🚩 In Function Names:
- `establish_connection` - obvious suspicious name
- `decode_string` - obfuscation indicator
- `install_persistence` - persistence mechanism

## Safe Testing Environment

**WARNING**: Only test in isolated lab environment!

### Setup Test (Optional):

**Terminal 1 - Attacker Simulation:**
```bash
# Install netcat if needed
nc -lvp 4444
```

**Terminal 2 - Run Backdoor:**
```bash
simple_backdoor.exe
```

**Try Commands:**
```bash
dir
whoami
ipconfig
exit
```

## Teaching Timeline (2-Hour Lab)

### Hour 1: IDA Pro Basics + Static Analysis
- **00-15 min**: IDA Pro interface introduction
- **15-30 min**: Imports and strings analysis (Ctrl+I, Shift+F12)
- **30-45 min**: Function list and suspicious functions
- **45-60 min**: Graph view basics

### Hour 2: Deep Dive + Hands-On
- **60-80 min**: Analyze `establish_connection()` function in detail
- **80-90 min**: Cross-reference analysis and data flow
- **90-120 min**: Student hands-on exercise

## Student Exercises

### Exercise 1: Basic Detection (15 minutes)
**Task**: Find evidence of backdoor behavior using only:
- Imports window
- Strings window
- Function list

**Questions**:
1. What network functions are imported?
2. What is the hardcoded IP and port?
3. Which function executes commands?

### Exercise 2: Graph Analysis (20 minutes)
**Task**: Analyze the `establish_connection` function
1. Draw the control flow on paper
2. Identify the command execution loop
3. Find the XOR decoding function

### Exercise 3: Detection Report (25 minutes)
**Task**: Write a 1-page malware analysis report including:
- Backdoor type (reverse shell)
- IOCs (Indicators of Compromise)
- YARA rule suggestions
- Mitigation recommendations

## IDA Pro Quick Reference Card

Print this for students:

```
Essential IDA Pro Shortcuts:
============================
Ctrl+I      → Imports window
Shift+F12   → Strings window
Shift+F3    → Functions list
Spacebar    → Toggle Text/Graph view
G           → Jump to address
X           → Cross-references
N           → Rename function/variable
;           → Add comment
:           → Enter comment
F5          → Hex-Rays decompiler (if available)
?           → Help

Mouse Controls:
===============
Double-click → Jump to location
Right-click  → Context menu
Scroll wheel → Zoom in graph view
Middle-drag  → Pan in graph view
```

## Troubleshooting

### Problem: Compilation Fails
**Solution**:
- Ensure GCC is installed: `gcc --version`
- Check you're in the correct directory
- Try running `compile.bat` as Administrator

### Problem: IDA Pro Won't Open File
**Solution**:
- Make sure anti-virus isn't blocking the .exe
- Try the `_debug.exe` version first
- Ensure you selected the correct processor (x86/x64)

### Problem: Can't Find Functions in IDA
**Solution**:
- Wait for auto-analysis to complete (progress bar at bottom)
- Try "Analysis → Reanalyze program"
- Use Shift+F3 to see all functions

## Additional Resources

### For Students:
- IDA Pro Free: https://hex-rays.com/ida-free/
- Malware analysis tutorials: https://malwareunicorn.org/
- Reverse engineering challenges: https://crackmes.one/

### For Instructors:
- Sample YARA rules for this backdoor type
- More complex samples: https://github.com/ytisf/theZoo (use with caution!)
- Automated analysis: https://www.hybrid-analysis.com/

## Next Steps

### For the Next Class:
1. **Advanced Obfuscation**: Show encrypted strings, packed binaries
2. **Dynamic Analysis**: Use x64dbg or OllyDbg for runtime analysis
3. **Network Analysis**: Wireshark capture of backdoor traffic
4. **YARA Rules**: Create detection rules based on findings

### Advanced Topics:
- Anti-debugging techniques
- Polymorphic code
- Rootkit detection
- Memory forensics with Volatility

## Assessment Ideas

### Assignment 1: Detection
Students must create a checklist of IOCs and detection methods

### Assignment 2: YARA Rules
Write YARA rules to detect similar backdoors

### Assignment 3: Remediation
Propose cleanup and prevention strategies

## Important Reminders

⚠️ **NEVER** run the backdoor on production systems
⚠️ **ALWAYS** use isolated VMs or lab networks
⚠️ **INFORM** students about legal and ethical implications
⚠️ **SUPERVISE** all malware analysis activities

## Contact & Support

For IDA Pro issues:
- Official docs: https://hex-rays.com/documentation/
- Community forum: https://forum.hex-rays.com/

For this educational package:
- Review the comprehensive guides in the IDA-Py folder
- All materials are designed for educational purposes only

---

**Good luck with your MSc cybersecurity course!** 🎓🔒
