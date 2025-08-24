import ctypes
from ctypes import wintypes
import pymem
import pymem.process
import re
import struct
import keyboard
import time

# Constants used for memory allocation and process access
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

# Windows API
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAllocEx.restype = wintypes.LPVOID

# Function to allocate memory near a target address
def allocate_near(pm: pymem.Pymem, base_addr: int, size: int=0x1000, search_range: int=0x7FFFFF00):
    start = base_addr & 0xFFFFFFFFFFFFF000
    offsets = [0]
    for i in range(1, search_range // 0x1000):
        offsets.append(i * 0x1000)
        offsets.append(-i * 0x1000)

    for offset in offsets:
        addr = start + offset
        if addr < 0x10000:
            continue
        mem = VirtualAllocEx(pm.process_handle, ctypes.c_void_p(addr), size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        if mem:
            print(f"[+] Allocated memory at near: 0x{mem:x}")
            return mem
    raise MemoryError("Could not allocate memory near target address")

# minecraft process
process_name = "Minecraft.Windows.exe"
pm = pymem.Pymem(process_name)
base_module = pymem.process.module_from_name(pm.process_handle, process_name)
base_address = base_module.lpBaseOfDll
module_size = base_module.SizeOfImage

# find aob pattern 
aob_pattern = b'\x0F\xB6\x42\x30\x41\x88\x41\x08'
bytes_read = pm.read_bytes(base_address, module_size)
matches = [m.start() for m in re.finditer(re.escape(aob_pattern), bytes_read)]
if not matches:
    print("[-] Pattern not found.")
    exit()

target_offset = matches[0]
target_address = base_address + target_offset
print(f"[+] Pattern found at: 0x{target_address:X}")

# Allocate new memory near the target address for our shellcode
newmem_addr = allocate_near(pm, target_address, 0x100)
print(f"[+] Allocated new memory near target: 0x{newmem_addr:X}")

#Calculate the return address for our shellcode
return_address = target_address + len(aob_pattern)
jmp_offset = newmem_addr - (target_address + 5)
if abs(jmp_offset) > 0x7FFFFFFF:
    print("[-] Still too far for relative jump. Abort.")
    exit()

# make shellcode
shellcode = b''
shellcode += b'\xB8\x01\x00\x00\x00'  # mov eax,1
shellcode += b'\x41\x88\x41\x08'      # mov [r9+08], al
shellcode += b'\xE9' + struct.pack('<i', return_address - (newmem_addr + 5))  # jmp return

pm.write_bytes(newmem_addr, shellcode, len(shellcode))
print("[+] Wrote shellcode.")

# jmp patch
jmp_patch = b'\xE9' + struct.pack('<i', jmp_offset) + b'\x90\x90\x90'
original_bytes = pm.read_bytes(target_address, len(jmp_patch))  # backup original bytes

sprint_enabled = False

def enable_sprint():
    pm.write_bytes(target_address, jmp_patch, len(jmp_patch))
    print("[+] Sprint enabled.")

def disable_sprint():
    pm.write_bytes(target_address, original_bytes, len(original_bytes))
    print("[+] Sprint disabled.")

def toggle_sprint():
    global sprint_enabled
    sprint_enabled = not sprint_enabled
    if sprint_enabled:
        enable_sprint()
    else:
        disable_sprint()
    print(f"[+] Sprint toggled {'ON' if sprint_enabled else 'OFF'}")

print("Press P to toggle sprint, ESC to exit.")

try:
    while True:
        if keyboard.is_pressed("p"):
            toggle_sprint()
            time.sleep(0.3)
        if keyboard.is_pressed("esc"):
            print("Exiting...")
            break
        time.sleep(0.05)
except KeyboardInterrupt:
    pass
finally:
    # when exiting, restore original bytes
    if sprint_enabled:
        disable_sprint()
    print("[*] Cleaned up, original bytes restored.")