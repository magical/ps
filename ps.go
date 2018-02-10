package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	PROCESS_VM_READ = 0x10
)

var psapi = windows.NewLazySystemDLL("psapi.dll")
var procEnumProcesses = psapi.NewProc("EnumProcesses")
var procEnumProcessModules = psapi.NewProc("EnumProcessModules")
var procGetModuleBaseName = psapi.NewProc("GetModuleBaseNameW")

func errno(e1 error) error {
	if e1, ok := e1.(syscall.Errno); ok && e1 == 0 {
		e1 = syscall.EINVAL
	}
	return e1
}

func EnumProcesses(pids []uint32) (n int, err error) {
	if len(pids) == 0 {
		return 0, nil
	}
	var outsize uint32
	r1, _, e1 := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids))*unsafe.Sizeof(pids[0]),
		uintptr(unsafe.Pointer(&outsize)),
	)
	if r1 == 0 {
		err = errno(e1)
	} else {
		n = int(uintptr(outsize) / unsafe.Sizeof(pids[0]))
	}
	return n, err
}

func EnumProcessModule(process windows.Handle) (h windows.Handle, err error) {
	var hmodule windows.Handle
	var needed int32
	r1, _, e1 := procEnumProcessModules.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(&hmodule)),
		4,
		uintptr(unsafe.Pointer(&needed)),
	)
	if r1 == 0 {
		err = errno(e1)
		return 0, err
	}
	return hmodule, nil
}

func GetModuleBaseName(process windows.Handle, module windows.Handle, outString *uint16, size uint32) (n int, err error) {
	r1, _, e1 := procGetModuleBaseName.Call(
		uintptr(process),
		uintptr(module),
		uintptr(unsafe.Pointer(outString)),
		uintptr(size),
	)
	if r1 == 0 {
		return 0, errno(e1)
	}
	return int(r1), nil
}

func main() {
	var pids []uint32 = make([]uint32, 1000)
	n, err := EnumProcesses(pids)
	if err != nil {
		fmt.Println(err)
		return
	}
	pids = pids[:n]
	//sort.Sort(Uint32Slice(pids))
	for _, id := range pids {
		if err := printInfo(id); err != nil {
			fmt.Println(id, err)
		}
	}
}

type SyscallError struct {
	call string
	err  error
}

func (e *SyscallError) Error() string {
	return fmt.Sprintf("%s: %v", e.call, e.err)
}

func printInfo(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)
	if err != nil {
		return &SyscallError{"OpenProcess", err}
	}
	defer windows.CloseHandle(h)
	mod, err := EnumProcessModule(h)
	if err != nil {
		return &SyscallError{"EnumProcessModule", err}
	}
	defer windows.CloseHandle(mod)
	//fmt.Println(mod, err)
	var s = make([]uint16, 255)
	n, err := GetModuleBaseName(h, mod, &s[0], uint32(len(s)))
	if err != nil {
		return &SyscallError{"GetModuleBaseName", err}
	}
	//fmt.Println(n, s[:n])
	fmt.Println(pid, windows.UTF16ToString(s[:n]))
	return nil
}

type Uint32Slice []uint32

func (s Uint32Slice) Len() int           { return len(s) }
func (s Uint32Slice) Less(i, j int) bool { return s[i] < s[j] }
func (s Uint32Slice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
