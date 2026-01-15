# Screenshot Guide for IDA Pro Demonstration

## Purpose
This guide tells you exactly what screenshots to take in IDA Pro and what they should show for your student documentation.

---

## HOW TO TAKE SCREENSHOTS

### Method 1: Windows Snipping Tool (Recommended)
1. Press `Windows Key + Shift + S`
2. Select the area to capture
3. Screenshot is copied to clipboard
4. Paste into Word document (Ctrl+V)

### Method 2: Full Screen
1. Press `Print Screen` key
2. Open Paint or Word
3. Paste (Ctrl+V)
4. Crop if needed

### Method 3: IDA Pro Built-in
1. In IDA Pro, go to the view you want to capture
2. Right-click → "Export to image" (if available)

---

## SCREENSHOTS TO TAKE - STEP BY STEP

---

## SCREENSHOT 1: IDA Pro Main Interface
**When**: Immediately after loading simple_backdoor_debug.exe
**What to show**:
- Full IDA Pro window
- Disassembly view showing code
- Hex view at bottom
- Functions window on left

**How to capture**:
1. Open IDA Pro: `D:\Forensics\ida.exe`
2. Load: `C:\Users\nwcla\Desktop\IDA-Py\simple_backdoor_debug.exe`
3. Wait for analysis to complete
4. Press `Windows Key + Shift + S`
5. Capture the entire IDA window

**Save as**: `01_IDA_Main_Interface.png`

**Caption for document**:
"Figure 1: IDA Pro main interface after loading simple_backdoor_debug.exe"

---

## SCREENSHOT 2: Imports Window
**When**: After pressing Ctrl+I
**What to show**:
- Imports window prominently displayed
- List of imported functions visible
- Highlight these suspicious imports:
  - WSAStartup
  - socket
  - connect
  - recv
  - send
  - _popen

**How to capture**:
1. In IDA Pro, press `Ctrl+I`
2. Imports window opens
3. Scroll to show ws2_32.dll and msvcrt.dll sections
4. Capture the Imports window

**Save as**: `02_Imports_Window.png`

**Annotations to add** (you can add these in Paint or Word):
- Red box around: WSAStartup, socket, connect
- Red box around: _popen
- Arrow pointing to connect with text "RED FLAG: Outbound connection!"
- Arrow pointing to _popen with text "CRITICAL: Command execution!"

**Caption for document**:
"Figure 2: Imports window showing suspicious networking (connect) and execution (_popen) functions"

---

## SCREENSHOT 3: Strings Window
**When**: After pressing Shift+F12
**What to show**:
- Strings window with all detected strings
- Visible suspicious strings like:
  - "Initializing Winsock"
  - "Connecting to %s:%d"
  - "Received command: %s"
  - "127.0.0.1"

**How to capture**:
1. In IDA Pro, press `Shift+F12`
2. Strings window opens
3. Scroll to show the suspicious strings
4. Capture the Strings window

**Save as**: `03_Strings_Window.png`

**Annotations to add**:
- Highlight "Received command: %s" in yellow
- Highlight "Connecting to %s:%d" in yellow
- Red box around IP address if visible

**Caption for document**:
"Figure 3: Strings window revealing network connection and command execution strings"

---

## SCREENSHOT 4: Functions List
**When**: After pressing Shift+F3
**What to show**:
- Functions window with list of all functions
- Sort by name (click "Name" column)
- Show these functions:
  - main
  - establish_connection
  - decode_string
  - check_system_updates
  - install_persistence

**How to capture**:
1. Press `Shift+F3`
2. Click "Name" column header to sort
3. Capture the Functions window

**Save as**: `04_Functions_List.png`

**Annotations to add**:
- Red box around: establish_connection
- Red box around: decode_string
- Red box around: install_persistence
- Green box around: check_system_updates (decoy function)
- Label: "Suspicious!" next to red boxed functions

**Caption for document**:
"Figure 4: Functions list showing obviously malicious function names"

---

## SCREENSHOT 5: Graph View Overview
**When**: After navigating to establish_connection and pressing Spacebar
**What to show**:
- Full graph view of establish_connection function
- All basic blocks visible
- Flow arrows showing execution path

**How to capture**:
1. Press `Shift+F3` (Functions window)
2. Double-click "establish_connection"
3. Press `Spacebar` to switch to Graph View
4. Press `-` (minus) to zoom out and fit entire function
5. Capture the full graph

**Save as**: `05_Graph_View_Overview.png`

**Annotations to add**:
- Label the entry block at top
- Circle the loop (back edge going upward)
- Arrow pointing to the loop with text "Command Loop - Infinite!"

**Caption for document**:
"Figure 5: Graph view of establish_connection showing control flow and command loop"

---

## SCREENSHOT 6: Winsock Initialization Block
**When**: Zoomed in on the WSAStartup block
**What to show**:
- Basic block containing:
  ```
  push    202h
  call    WSAStartup
  test    eax, eax
  ```

**How to capture**:
1. In graph view of establish_connection
2. Zoom in on the first significant block (after prologue)
3. Should show WSAStartup call
4. Capture just this block

**Save as**: `06_Winsock_Init_Block.png`

**Annotations to add**:
- Highlight "call WSAStartup" in yellow
- Label: "Network initialization"

**Caption for document**:
"Figure 6: WSAStartup call initializing Windows networking"

---

## SCREENSHOT 7: Socket Creation Block
**When**: Block showing socket() call
**What to show**:
- Basic block with:
  ```
  push    0
  push    1        ; SOCK_STREAM
  push    2        ; AF_INET
  call    socket
  ```

**How to capture**:
1. Scroll to block with socket() call
2. Capture just this block

**Save as**: `07_Socket_Creation.png`

**Annotations to add**:
- Highlight "call socket"
- Arrow to "push 1" with label "TCP (SOCK_STREAM)"
- Arrow to "push 2" with label "IPv4 (AF_INET)"

**Caption for document**:
"Figure 7: TCP socket creation"

---

## SCREENSHOT 8: Connect Block (CRITICAL!)
**When**: Block showing connect() call
**What to show**:
- Basic block with:
  ```
  [setting up sockaddr_in structure]
  call    connect
  test    eax, eax
  ```

**How to capture**:
1. Scroll to block with connect() call
2. Capture this block and the conditional branches after it

**Save as**: `08_Connect_Block.png`

**Annotations to add**:
- Big red box around "call connect"
- Label: "⚠️ OUTBOUND CONNECTION - Reverse Shell!"
- Highlight IP address and port setup above the call

**Caption for document**:
"Figure 8: Critical connect() call establishing outbound connection to attacker (reverse shell pattern)"

---

## SCREENSHOT 9: Command Loop - Full View
**When**: Showing the entire recv → execute → send loop
**What to show**:
- Multiple blocks showing:
  1. recv() call
  2. check for "exit"
  3. _popen() call
  4. fgets() to read output
  5. send() call
  6. back edge to recv()

**How to capture**:
1. Zoom to show all blocks in the loop
2. Make sure the back-edge (upward arrow) is visible
3. Capture

**Save as**: `09_Command_Loop_Full.png`

**Annotations to add**:
- Number the blocks: 1, 2, 3, 4, 5
- Big arrow following the loop path
- Label: "Command Execution Loop"
- Highlight the back edge with text "Infinite loop!"

**Caption for document**:
"Figure 9: Complete command execution loop showing recv → execute → send pattern"

---

## SCREENSHOT 10: recv() Block
**When**: Zoomed in on recv() call
**What to show**:
- Block with recv() call and parameters

**How to capture**:
1. Zoom in on block containing recv()
2. Capture

**Save as**: `10_Recv_Block.png`

**Annotations to add**:
- Highlight "call recv"
- Label: "Receive command from attacker"

**Caption for document**:
"Figure 10: recv() call waiting for commands from remote attacker"

---

## SCREENSHOT 11: _popen() Block (CRITICAL!)
**When**: Block showing _popen() call
**What to show**:
- Block with:
  ```
  lea     eax, [ebp+recvbuf]
  push    offset "r"
  push    eax
  call    _popen
  ```

**How to capture**:
1. Zoom in on _popen block
2. Show the instructions loading the buffer
3. Capture

**Save as**: `11_Popen_Execution.png`

**Annotations to add**:
- Big red box around "call _popen"
- Arrow from buffer parameter to _popen
- Label: "⚠️ EXECUTES ATTACKER'S COMMAND - NO VALIDATION!"
- Highlight that recvbuf goes directly to _popen

**Caption for document**:
"Figure 11: _popen() directly executing commands received from network with NO validation"

---

## SCREENSHOT 12: send() Block
**When**: Block showing send() sending results back
**What to show**:
- Block with send() call sending command output

**How to capture**:
1. Zoom in on send() block
2. Capture

**Save as**: `12_Send_Results.png`

**Annotations to add**:
- Highlight "call send"
- Label: "Send command output back to attacker"

**Caption for document**:
"Figure 12: send() transmitting command execution results back to attacker"

---

## SCREENSHOT 13: Cross-References Window
**When**: After pressing X on _popen
**What to show**:
- Cross-references window showing where _popen is called

**How to capture**:
1. Navigate to _popen in imports (Ctrl+I)
2. Double-click _popen
3. Press `X` key
4. Cross-references window appears
5. Capture the window

**Save as**: `13_Cross_References.png`

**Annotations to add**:
- Highlight the reference from establish_connection

**Caption for document**:
"Figure 13: Cross-references showing _popen is called from establish_connection function"

---

## SCREENSHOT 14: decode_string Function Graph
**When**: Graph view of decode_string function
**What to show**:
- Small graph showing XOR decoding loop

**How to capture**:
1. Navigate to decode_string function
2. Press Spacebar for graph view
3. Capture

**Save as**: `14_Decode_String_XOR.png`

**Annotations to add**:
- Highlight the XOR instruction
- Label: "XOR decoding loop - String obfuscation"
- Circle the loop back-edge

**Caption for document**:
"Figure 14: decode_string function showing XOR-based string obfuscation"

---

## SCREENSHOT 15: Hex View with Data
**When**: Showing encoded strings in hex view
**What to show**:
- Hex view at bottom of IDA
- Show the XOR-encoded IP address data

**How to capture**:
1. Find the encoded IP string data section
2. Show hex values
3. Capture hex view panel

**Save as**: `15_Hex_View_Encoded.png`

**Caption for document**:
"Figure 15: Hex view showing XOR-encoded string data"

---

## SCREENSHOT 16: Complete Program Flow (Optional)
**When**: Using Proximity Browser or creating custom diagram
**What to show**:
- High-level flow: main → decode_string → establish_connection

**How to capture**:
1. View → Open subviews → Proximity Browser
2. Navigate to main function
3. Capture

**Save as**: `16_Program_Flow.png`

**Caption for document**:
"Figure 16: High-level program flow from main to malicious functions"

---

## ORGANIZING YOUR SCREENSHOTS

### Folder Structure:
```
C:\Users\nwcla\Desktop\IDA-Py\
├── screenshots\
│   ├── 01_IDA_Main_Interface.png
│   ├── 02_Imports_Window.png
│   ├── 03_Strings_Window.png
│   ├── 04_Functions_List.png
│   ├── 05_Graph_View_Overview.png
│   ├── 06_Winsock_Init_Block.png
│   ├── 07_Socket_Creation.png
│   ├── 08_Connect_Block.png
│   ├── 09_Command_Loop_Full.png
│   ├── 10_Recv_Block.png
│   ├── 11_Popen_Execution.png
│   ├── 12_Send_Results.png
│   ├── 13_Cross_References.png
│   ├── 14_Decode_String_XOR.png
│   ├── 15_Hex_View_Encoded.png
│   └── 16_Program_Flow.png
```

---

## ADDING SCREENSHOTS TO YOUR DOCUMENT

### In Microsoft Word:

1. Open your DOCX document (converted from IDA_DEMO_STEPS.txt)

2. Find the relevant section

3. Insert screenshot:
   - Click where you want the image
   - Insert → Pictures → Browse
   - Select the screenshot file
   - Click Insert

4. Format the screenshot:
   - Right-click image → Wrap Text → Top and Bottom
   - Resize if needed (drag corners)
   - Center align

5. Add caption below:
   - Click below image
   - References → Insert Caption
   - Type the caption text

### Screenshot Placement in Document:

```
SECTION 2: Loading the Binary
[Screenshot 01: IDA Pro Main Interface]

SECTION 3: Import Analysis
[Screenshot 02: Imports Window - annotated]

SECTION 4: String Analysis
[Screenshot 03: Strings Window]

SECTION 5: Function Analysis
[Screenshot 04: Functions List - annotated]

SECTION 6: Graph View Analysis
[Screenshot 05: Graph View Overview]
[Screenshot 06: Winsock Init Block]
[Screenshot 07: Socket Creation]
[Screenshot 08: Connect Block - annotated with red flag]
[Screenshot 09: Command Loop Full]
[Screenshot 10: recv() Block]
[Screenshot 11: _popen() Block - critical annotation]
[Screenshot 12: send() Block]

SECTION 7: Cross-Reference Analysis
[Screenshot 13: Cross-References Window]

Additional:
[Screenshot 14: decode_string XOR loop]
[Screenshot 15: Hex View]
[Screenshot 16: Program Flow]
```

---

## QUICK SCREENSHOT CHECKLIST

Before your class, capture all 16 screenshots:

- [ ] Screenshot 1: IDA Main Interface
- [ ] Screenshot 2: Imports Window (annotated)
- [ ] Screenshot 3: Strings Window
- [ ] Screenshot 4: Functions List (annotated)
- [ ] Screenshot 5: Graph View Overview
- [ ] Screenshot 6: Winsock Init Block
- [ ] Screenshot 7: Socket Creation
- [ ] Screenshot 8: Connect Block (heavily annotated)
- [ ] Screenshot 9: Command Loop Full (annotated)
- [ ] Screenshot 10: recv() Block
- [ ] Screenshot 11: _popen() Block (critical annotations)
- [ ] Screenshot 12: send() Block
- [ ] Screenshot 13: Cross-References
- [ ] Screenshot 14: XOR decode loop
- [ ] Screenshot 15: Hex View
- [ ] Screenshot 16: Program Flow

---

## TOOLS FOR ANNOTATIONS

### Option 1: Microsoft Paint (Simple)
1. Open screenshot in Paint
2. Use text tool to add labels
3. Use rectangle tool for boxes
4. Use line tool for arrows
5. Save

### Option 2: Microsoft Word (Easy)
1. Insert screenshot in Word
2. Insert → Shapes → Add arrows, boxes, text
3. Right-click image → "Send to Back" so shapes appear on top

### Option 3: Snagit (Professional)
- Advanced screenshot and annotation tool
- Costs money but very powerful

### Option 4: PowerPoint (Recommended)
1. Insert screenshot in PowerPoint
2. Use drawing tools to annotate
3. Right-click → Save as Picture
4. Import annotated version to Word

---

## EXAMPLE ANNOTATION GUIDE

### For Screenshot 8 (Connect Block):

#### What to add:
1. **Red rectangle** around "call connect"
2. **Red arrow** pointing to it
3. **Text label** in red: "⚠️ OUTBOUND CONNECTION"
4. **Text label**: "This is a REVERSE SHELL!"
5. **Yellow highlight** on IP address setup
6. **Yellow highlight** on port setup

#### Colors to use:
- 🔴 Red: Dangerous/critical functions
- 🟡 Yellow: Important but not critical
- 🟢 Green: Safe/legitimate code
- 🔵 Blue: Informational labels

---

## TIME ESTIMATE

Taking all 16 screenshots: **30-45 minutes**
- Opening IDA Pro: 5 min
- Capturing screenshots: 20-30 min
- Basic annotations: 15-20 min

**Total**: About 1 hour to complete all screenshots

---

## NEED HELP?

If you need assistance:
1. Take the screenshots first (even without annotations)
2. You can add annotations later
3. The most critical screenshots are:
   - #2 (Imports)
   - #8 (Connect block)
   - #11 (_popen block)
   - #9 (Command loop)

Start with these 4 if you're short on time!

---

Ready to take your screenshots? Follow this guide step by step!
