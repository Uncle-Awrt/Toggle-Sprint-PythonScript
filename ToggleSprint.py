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

VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
VirtualProtectEx.restype = wintypes.BOOL

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

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

# find aob pattern 1: 41 80 7B 17 00
aob_pattern1 = b'\x41\x80\x7B\x17\x00'
bytes_read = pm.read_bytes(base_address, module_size)
matches1 = [m.start() for m in re.finditer(re.escape(aob_pattern1), bytes_read)]

if not matches1:
    print("[-] Pattern 1 not found.")
    exit()

target_address1 = base_address + matches1[0]
print(f"[+] Pattern 1 found at: 0x{target_address1:X}")

# find aob pattern 2: 41 8B 03 33 C9
aob_pattern2 = b'\x41\x8B\x03\x33\xC9'
matches2 = [m.start() for m in re.finditer(re.escape(aob_pattern2), bytes_read)]

if not matches2:
    print("[-] Pattern 2 not found.")
    exit()

target_address2 = base_address + matches2[0]
print(f"[+] Pattern 2 found at: 0x{target_address2:X}")

# backup original bytes
original_bytes1 = pm.read_bytes(target_address1, 5)
original_bytes2 = pm.read_bytes(target_address2, 3)

injection_enabled = False

def enable_injection():
    # Patch 1: NOP 5 bytes
    old_protect1 = wintypes.DWORD()
    VirtualProtectEx(pm.process_handle, ctypes.c_void_p(target_address1), 5, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect1))
    
    nop_patch1 = b'\x90\x90\x90\x90\x90'
    try:
        pm.write_bytes(target_address1, nop_patch1, len(nop_patch1))
    except:
        bytes_written = ctypes.c_size_t()
        WriteProcessMemory(pm.process_handle, ctypes.c_void_p(target_address1), nop_patch1, len(nop_patch1), ctypes.byref(bytes_written))
    
    VirtualProtectEx(pm.process_handle, ctypes.c_void_p(target_address1), 5, old_protect1.value, ctypes.byref(old_protect1))
    
    # Patch 2: NOP 3 bytes
    old_protect2 = wintypes.DWORD()
    VirtualProtectEx(pm.process_handle, ctypes.c_void_p(target_address2), 3, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect2))
    
    nop_patch2 = b'\x90\x90\x90'
    try:
        pm.write_bytes(target_address2, nop_patch2, len(nop_patch2))
    except:
        bytes_written = ctypes.c_size_t()
        WriteProcessMemory(pm.process_handle, ctypes.c_void_p(target_address2), nop_patch2, len(nop_patch2), ctypes.byref(bytes_written))
    
    VirtualProtectEx(pm.process_handle, ctypes.c_void_p(target_address2), 3, old_protect2.value, ctypes.byref(old_protect2))
    
    print("[+] Injection enabled.")

def disable_injection():
    # Restore patch 1
    old_protect1 = wintypes.DWORD()
    VirtualProtectEx(pm.process_handle, ctypes.c_void_p(target_address1), 5, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect1))
    
    try:
        pm.write_bytes(target_address1, original_bytes1, len(original_bytes1))
    except:
        bytes_written = ctypes.c_size_t()
        WriteProcessMemory(pm.process_handle, ctypes.c_void_p(target_address1), original_bytes1, len(original_bytes1), ctypes.byref(bytes_written))
    
    VirtualProtectEx(pm.process_handle, ctypes.c_void_p(target_address1), 5, old_protect1.value, ctypes.byref(old_protect1))
    
    # Restore patch 2
    old_protect2 = wintypes.DWORD()
    VirtualProtectEx(pm.process_handle, ctypes.c_void_p(target_address2), 3, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect2))
    
    try:
        pm.write_bytes(target_address2, original_bytes2, len(original_bytes2))
    except:
        bytes_written = ctypes.c_size_t()
        WriteProcessMemory(pm.process_handle, ctypes.c_void_p(target_address2), original_bytes2, len(original_bytes2), ctypes.byref(bytes_written))
    
    VirtualProtectEx(pm.process_handle, ctypes.c_void_p(target_address2), 3, old_protect2.value, ctypes.byref(old_protect2))
    
    print("[+] Injection disabled.")

def toggle_injection():
    global injection_enabled
    injection_enabled = not injection_enabled
    if injection_enabled:
        enable_injection()
    else:
        disable_injection()
    print(f"[+] Injection toggled {'ON' if injection_enabled else 'OFF'}")

print("Press P to toggle injection, ESC to exit.")

try:
    while True:
        if keyboard.is_pressed("p"):
            toggle_injection()
            time.sleep(0.3)
        if keyboard.is_pressed("esc"):
            print("Exiting...")
            break
        time.sleep(0.05)
except KeyboardInterrupt:
    pass
finally:
    # when exiting, restore original bytes
    if injection_enabled:
        disable_injection()
    print("[*] Cleaned up, original bytes restored.")