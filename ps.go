package main

import (
	"fmt"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

var psapi = windows.NewLazySystemDLL("psapi.dll")
var procEnumProcesses = psapi.NewProc("EnumProcesses")

func EnumProcesses(pids []uint32) (n int, err error) {
	if len(pids) == 0 {
		return 0, nil
	}
	var outsize uint32
	_, _, err = procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids))*unsafe.Sizeof(pids[0]),
		uintptr(unsafe.Pointer(&outsize)),
	)
	n = int(uintptr(outsize) / unsafe.Sizeof(pids[0]))
	return n, err
}

func main() {
	var pids []uint32 = make([]uint32, 1000)
	n, err := EnumProcesses(pids)
	if err != nil {
		fmt.Println(err)
		return
	}
	pids = pids[:n]
	sort.Sort(Uint32Slice(pids))
	for _, id := range pids {
		printInfo(pid)
	}
}

func printInfo(pid int32) error {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	fmt.Println()
}

type Uint32Slice []uint32

func (s Uint32Slice) Len() int           { return len(s) }
func (s Uint32Slice) Less(i, j int) bool { return s[i] < s[j] }
func (s Uint32Slice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
