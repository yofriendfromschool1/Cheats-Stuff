# NanoButton Sulution

## Running Binary
- Running binary will start playing sound and open button in middle of screen saying "Hi"
- after pressing the button a messagebox with text "Maybe something wrong..." will pop up.

## Analyzing Binary
- load NanoButton.exe into x32dbg
- need to run to unpack the UPX compressed content to get usefull diassembly
    - press run a couple of times (skip default breakpoints) until sound is playing and 'Hi'button pops up.
- need to get back to user code in disassembly to find the address, where user code calls a dll function to open the message box.
    - Pause binary, then press 'Run to user code'.
    - need to click the 'Hi' button and confirm the 'MAybe something wrong..." message.
    - EIP will be in user code after the call displaying the message box.
- need to look around in the disassembly to find out where the message box gets the displayed text.
    - scrolling up in disassembly shows `00401448 | E8 BB010000 | call <JMP.&MessageBoxA> |`
    - three lines above `00401439 | C74424 04 47604000 | mov dword ptr ss:[esp+4],nanobutton.406047 | 406047:"Maybe something wrong...` "
- need to find a compare and a conditional jump where the code will bypass loading this string.
    - this can be found a couple of lines up
      `00401420 | 803D 08804000 00         | cmp byte ptr ds:[408008],0                 |`
      `00401427 | 75 33                    | jne nanobutton.40145C                      |`
    - jumping to `nanobutton.40145C` would bypass the loading of the string

## Trial and error patching
- let's see what happens if we invert the condition of the jump
    - replace jne at adderess 0x00401427 with jmp and see what happens.
    - fortunately the message box will display ":3". So this is the only patch required.

## Making a Patcher
- Since NanoButton.exe is compressed before execution it is not possible to simpy apply a patch directly.
     - a solution could be to start the executable and apply the patch in this state, same as done manually in x32dbg.
- Radare2 has a Python plug-in (pip install r2pipe) which is suitable for this purpose.
    - creating a simple Pythpn script can exactly run the steps required to apply the required patch to the running binary.

## Python - r2pipe script

```python
#!/usr/bin/env python3

import r2pipe

r = r2pipe.open('NanoButton.exe' , flags=['-w', '-d'])
r.cmd('2dc; db entry1; 3dc')   #  run, set break at entry1, run
r.cmd('s 0x401427')                 # skip to adress where code needs to be pacthed 
print(r.cmd('pd 3'))                # dump disassembly before patching
r.cmd('wao recj')                   # invert jne to je
print(r.cmd('pd 3'))                # dump disassembly after patching
r.cmd('dbid 0; 2dc')                # disable breakpoint and run
r.cmd('Q')                          # quit after executable is terminated with alt+F4
```

