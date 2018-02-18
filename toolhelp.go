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
