{ Game   : Minecraft.Windows.exe
  Version:
  Date   : 2025-12-07
  Author : Uncle Awrt
  This script combines two injection points
}

[ENABLE]
aobscanmodule(INJECT1,Minecraft.Windows.exe,41 80 7B 17 00 75 17 41 8B 03 33 C9)
alloc(newmem,$1000,INJECT1)

label(code)
label(return)

newmem:
code:
  cmp byte ptr [r11+17],00
  jne short @f
  mov eax,[r11]
  xor ecx,ecx
@@:
  jmp return

INJECT1:
  db 90 90 90 90 90 90 90 90 90 90 90 90
return:

registersymbol(INJECT1)

[DISABLE]
INJECT1:
  db 41 80 7B 17 00 75 17 41 8B 03 33 C9
unregistersymbol(INJECT1)
dealloc(newmem)

{
// ORIGINAL CODE - INJECTION POINTS:
// Minecraft.Windows.exe+2B07EE3 and Minecraft.Windows.exe+2B07EEA

Minecraft.Windows.exe+2B07EDC: 41 80 7B 16 00           - cmp byte ptr [r11+16],00
Minecraft.Windows.exe+2B07EE1: 75 1E                    - jne Minecraft.Windows.exe+2B07F01
Minecraft.Windows.exe+2B07EE3: 41 80 7B 17 00           - cmp byte ptr [r11+17],00
Minecraft.Windows.exe+2B07EE8: 75 17                    - jne Minecraft.Windows.exe+2B07F01
Minecraft.Windows.exe+2B07EEA: 41 8B 03                 - mov eax,[r11]
Minecraft.Windows.exe+2B07EED: 33 C9                    - xor ecx,ecx
Minecraft.Windows.exe+2B07EEF: 85 C0                    - test eax,eax
Minecraft.Windows.exe+2B07EF1: 0F 9E C1                 - setle cl
Minecraft.Windows.exe+2B07EF4: FF C1                    - inc ecx
}