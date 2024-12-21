import os
import argparse
import pefile
import psutil
from tabulate import tabulate
import ctypes
from ctypes import wintypes
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Windows API structures and functions for retrieving loaded module information
class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                ("SizeOfImage", wintypes.DWORD),
                ("EntryPoint", ctypes.c_void_p)]


# Load required Windows API functions
psapi = ctypes.WinDLL('psapi')
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Define function prototypes
psapi.EnumProcessModulesEx.restype = wintypes.BOOL
psapi.EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE),
                                       wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]

psapi.GetModuleInformation.restype = wintypes.BOOL
psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                       ctypes.POINTER(MODULEINFO), wintypes.DWORD]

psapi.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                     ctypes.c_wchar_p, wintypes.DWORD]

psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                       ctypes.c_wchar_p, wintypes.DWORD]


class MemoryProtectionCheck:

    def __init__(self, pid):
        self.pid = pid

    def get_loaded_modules(self):
        """Retrieve all loaded modules for a process using the Windows API."""
        modules = []
        process_handle = kernel32.OpenProcess(0x0410, False, self.pid)  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        if not process_handle:
            raise PermissionError(f"Could not open process {self.pid}: {ctypes.get_last_error()}")

        try:
            h_module_array = (wintypes.HMODULE * 1024)()
            cb_needed = wintypes.DWORD()

            if not psapi.EnumProcessModulesEx(process_handle, h_module_array, ctypes.sizeof(h_module_array),
                                              ctypes.byref(cb_needed), 0x03):  # LIST_MODULES_ALL
                raise OSError(f"Failed to enumerate modules: {ctypes.get_last_error()}")

            module_count = cb_needed.value // ctypes.sizeof(wintypes.HMODULE)

            for i in range(module_count):
                h_module = h_module_array[i]

                # Get module base name
                module_name = ctypes.create_unicode_buffer(260)
                psapi.GetModuleBaseNameW(process_handle, h_module, module_name, ctypes.sizeof(module_name))

                # Get module file path
                module_path = ctypes.create_unicode_buffer(260)
                psapi.GetModuleFileNameExW(process_handle, h_module, module_path, ctypes.sizeof(module_path))

                # Get module information (base address)
                mod_info = MODULEINFO()
                if psapi.GetModuleInformation(process_handle, h_module, ctypes.byref(mod_info), ctypes.sizeof(mod_info)):
                    modules.append({
                        "name": module_name.value,
                        "path": module_path.value,
                        "base_address": hex(mod_info.lpBaseOfDll)
                    })

        finally:
            kernel32.CloseHandle(process_handle)

        return modules

    def analyze_module(self, file, module_name, base_address):
        try:
            pe = pefile.PE(file)
        except pefile.PEFormatError:
            return {
                "Module": module_name,
                "Base Address": base_address,
                "ASLR": "N/A",
                "DEP": "N/A",
                "SafeSEH": "N/A",
                "Rebase": "N/A",
                "Memory Protected": "N/A"
            }
        except Exception as e:
            return {
                "Module": module_name,
                "Base Address": base_address,
                "ASLR": f"Error: {e}",
                "DEP": "N/A",
                "SafeSEH": "N/A",
                "Rebase": "N/A",
                "Memory Protected": "Unknown"
            }

        # Extract DllCharacteristics and flags
        dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
        aslr_enabled = dll_char & 0x0040
        safeseh_enabled = dll_char & 0x0400
        dep_enabled = dll_char & 0x0100
        rebase_enabled = dll_char & 0x0020

        memory_protected = "Yes" if aslr_enabled and dep_enabled and safeseh_enabled else "No"

        return {
            "Module": module_name,
            "Base Address": base_address,
            "ASLR": "Enabled" if aslr_enabled else "Disabled",
            "DEP": "Enabled" if dep_enabled else "Disabled",
            "SafeSEH": "Enabled" if safeseh_enabled else "Disabled",
            "Rebase": "Enabled" if rebase_enabled else "Disabled",
            "Memory Protected": memory_protected
        }

    def analyze_loaded_modules(self):
        try:
            process = psutil.Process(self.pid)
        except psutil.NoSuchProcess:
            print(f"Error: No process found with PID {self.pid}.")
            return
        except Exception as e:
            print(f"Error: Unable to attach to process: {e}")
            return

        print(f"\nAnalyzing loaded modules for PID {self.pid} ({process.name()}):\n")
        user_dll_analysis = []
        system_dll_analysis = []

        try:
            modules = self.get_loaded_modules()
            for module in modules:
                module_path = module["path"]
                module_name = module["name"]
                base_address = module["base_address"]

                # Classify user-based DLLs vs system DLLs
                if "System32" in module_path or "Windows" in module_path:
                    category = "System DLL"
                else:
                    category = "User DLL"

                # Analyze the module
                if os.path.isfile(module_path):
                    analysis = self.analyze_module(module_path, module_name, base_address)

                    # Append the analysis results
                    if category == "User DLL":
                        user_dll_analysis.append(analysis)
                    else:
                        system_dll_analysis.append(analysis)

        except PermissionError as e:
            print(e)
        except OSError as e:
            print(e)

        # Print categorized results
        print("\nUser DLLs:\n")
        if user_dll_analysis:
            self.print_table(user_dll_analysis)
        else:
            print("No user DLLs found or insufficient permissions to access them.")

        print("\nSystem DLLs:\n")
        if system_dll_analysis:
            self.print_table(system_dll_analysis)
        else:
            print("No system DLLs found or insufficient permissions to access them.")

    def print_table(self, data):
        table_data = []
        for analysis in data:
            table_data.append([
                Fore.CYAN + analysis["Module"] + Style.RESET_ALL,
                Fore.YELLOW + analysis["Base Address"] + Style.RESET_ALL,
                Fore.GREEN + analysis["ASLR"] if analysis["ASLR"] == "Enabled" else Fore.RED + analysis["ASLR"],
                Fore.GREEN + analysis["DEP"] if analysis["DEP"] == "Enabled" else Fore.RED + analysis["DEP"],
                Fore.GREEN + analysis["SafeSEH"] if analysis["SafeSEH"] == "Enabled" else Fore.RED + analysis["SafeSEH"],
                Fore.GREEN + analysis["Rebase"] if analysis["Rebase"] == "Enabled" else Fore.RED + analysis["Rebase"]
            ])
        print(tabulate(table_data, headers=["Module", "Base Address", "ASLR", "DEP", "SafeSEH", "Rebase"], tablefmt="grid"))


def main():
    parser = argparse.ArgumentParser(description="Analyze loaded modules for memory protection features and base address.")
    parser.add_argument("pid", type=int, help="PID of the process to analyze.")
    args = parser.parse_args()

    memory_check = MemoryProtectionCheck(args.pid)
    memory_check.analyze_loaded_modules()


if __name__ == "__main__":
    main()
memory_analysis = MemoryProtectionCheck