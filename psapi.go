package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	PROCESS_VM_READ = 0x10
)

var psapi = windows.NewLazySystemDLL("psapi.dll")

var (
	procEnumProcesses      = psapi.NewProc("EnumProcesses")
	procEnumProcessModules = psapi.NewProc("EnumProcessModules")
	procGetModuleBaseName  = psapi.NewProc("GetModuleBaseNameW")
)

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
