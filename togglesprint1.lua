{ Game   : Minecraft.Windows.exe
  Version: 
  Date   : 2025-12-07
  Author : Uncle Awrt

  This script does blah blah blah
}

[ENABLE]

aobscanmodule(INJECT,Minecraft.Windows.exe,41 80 7B 17 00) // should be unique
alloc(newmem,$1000,INJECT)

label(code)
label(return)

newmem:

code:
  cmp byte ptr [r11+17],00
  jmp return

INJECT:
  db 90 90 90 90 90
return:
registersymbol(INJECT)

[DISABLE]

INJECT:
  db 41 80 7B 17 00

unregistersymbol(INJECT)
dealloc(newmem)

{
// ORIGINAL CODE - INJECTION POINT: Minecraft.Windows.exe+2B07EE3

Minecraft.Windows.exe+2B07EC4: EB 48                    - jmp Minecraft.Windows.exe+2B07F0E
Minecraft.Windows.exe+2B07EC6: 84 C0                    - test al,al
Minecraft.Windows.exe+2B07EC8: 75 12                    - jne Minecraft.Windows.exe+2B07EDC
Minecraft.Windows.exe+2B07ECA: 84 DB                    - test bl,bl
Minecraft.Windows.exe+2B07ECC: 75 0E                    - jne Minecraft.Windows.exe+2B07EDC
Minecraft.Windows.exe+2B07ECE: 48 8B 84 24 80 00 00 00  - mov rax,[rsp+00000080]
Minecraft.Windows.exe+2B07ED6: F6 40 04 01              - test byte ptr [rax+04],01
Minecraft.Windows.exe+2B07EDA: 74 25                    - je Minecraft.Windows.exe+2B07F01
Minecraft.Windows.exe+2B07EDC: 41 80 7B 16 00           - cmp byte ptr [r11+16],00
Minecraft.Windows.exe+2B07EE1: 75 1E                    - jne Minecraft.Windows.exe+2B07F01
// ---------- INJECTING HERE ----------
Minecraft.Windows.exe+2B07EE3: 41 80 7B 17 00           - cmp byte ptr [r11+17],00
// ---------- DONE INJECTING  ----------
Minecraft.Windows.exe+2B07EE8: 75 17                    - jne Minecraft.Windows.exe+2B07F01
Minecraft.Windows.exe+2B07EEA: 41 8B 03                 - mov eax,[r11]
Minecraft.Windows.exe+2B07EED: 33 C9                    - xor ecx,ecx
Minecraft.Windows.exe+2B07EEF: 85 C0                    - test eax,eax
Minecraft.Windows.exe+2B07EF1: 0F 9E C1                 - setle cl
Minecraft.Windows.exe+2B07EF4: FF C1                    - inc ecx
Minecraft.Windows.exe+2B07EF6: 85 C0                    - test eax,eax
Minecraft.Windows.exe+2B07EF8: 7F B4                    - jg Minecraft.Windows.exe+2B07EAE
Minecraft.Windows.exe+2B07EFA: 41 C7 03 07 00 00 00     - mov [r11],00000007
Minecraft.Windows.exe+2B07F01: 45 88 7A 08              - mov [r10+08],r15b
}