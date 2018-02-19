package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var kernel32 = windows.NewLazySystemDLL("kernel32.dll")

var (
	procThread32First = kernel32.NewProc("Thread32First")
	procThread32Next  = kernel32.NewProc("Thread32Next")
)

type ThreadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePriority   int32
	DeltaPriority  int32
	Flags          uint32
}

func Thread32First(snapshot windows.Handle, procEntry *ThreadEntry32) (err error) {
	r1, _, e1 := syscall.Syscall(procThread32First.Addr(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(procEntry)), 0)
	if r1 == 0 {
		err = errno(e1)
	}
	return
}

func Thread32Next(snapshot windows.Handle, procEntry *ThreadEntry32) (err error) {
	r1, _, e1 := syscall.Syscall(procThread32Next.Addr(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(procEntry)), 0)
	if r1 == 0 {
		err = errno(e1)
	}
	return
}

///// not actually part of toolhelp

var procVirtualQueryEx = kernel32.NewProc("VirtualQueryEx")

//https://msdn.microsoft.com/en-us/library/windows/desktop/aa366775(v=vs.85).aspx
const (
	MEM_FREE    = 0x100 << 8
	MEM_COMMIT  = 0x10 << 8
	MEM_RESERVE = 0x20 << 8

	MEM_IMAGE   = 0x100 << 16
	MEM_MAPPED  = 0x4 << 16
	MEM_PRIVATE = 0x2 << 16
)

type MemoryBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func VirtualQueryEx(process windows.Handle, address uintptr, buffer *MemoryBasicInfo) (err error) {
	r1, _, e1 := procVirtualQueryEx.Call(
		uintptr(process),
		address,
		uintptr(unsafe.Pointer(buffer)),
		unsafe.Sizeof(*buffer),
	)
	if r1 == 0 {
		err = errno(e1)
	}
	return
}
