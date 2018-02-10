package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

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
		name, err := getProcessName(id)
		if err != nil {
			fmt.Println(id, err)
		} else {
			fmt.Println(id, name)
			printModules(id)
		}
	}
}

type Uint32Slice []uint32

func (s Uint32Slice) Len() int           { return len(s) }
func (s Uint32Slice) Less(i, j int) bool { return s[i] < s[j] }
func (s Uint32Slice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

type SyscallError struct {
	call string
	err  error
}

func (e *SyscallError) Error() string {
	return fmt.Sprintf("%s: %v", e.call, e.err)
}

func getProcessName(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)
	if err != nil {
		return "", &SyscallError{"OpenProcess", err}
	}
	defer windows.CloseHandle(h)
	mod, err := EnumProcessModule(h)
	if err != nil {
		return "", &SyscallError{"EnumProcessModule", err}
	}
	defer windows.CloseHandle(mod)
	//fmt.Println(mod, err)
	var s = make([]uint16, 255)
	n, err := GetModuleBaseName(h, mod, &s[0], uint32(len(s)))
	if err != nil {
		return "", &SyscallError{"GetModuleBaseName", err}
	}
	return windows.UTF16ToString(s[:n]), nil
}

func printModules(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)
	if err != nil {
		return &SyscallError{"OpenProcess", err}
	}
	defer windows.CloseHandle(h)
	modules := make([]windows.Handle, 255)
	n, err := EnumProcessModules(h, modules)
	if err != nil {
		return &SyscallError{"EnumProcessModules", err}
	}
	if n < len(modules) {
		modules = modules[:n]
	}
	defer func() {
		for _, mod := range modules {
			windows.CloseHandle(mod)
		}
	}()
	var buf = make([]uint16, 255)
	for i, mod := range modules {
		//fmt.Println(mod, err)
		n, err := GetModuleBaseName(h, mod, &buf[0], uint32(len(buf)))
		if err != nil {
			return &SyscallError{"GetModuleBaseName", err}
		}
		s := windows.UTF16ToString(buf[:n])
		fmt.Printf("\t%d: %s\n", i, s)
	}
	return nil
}
