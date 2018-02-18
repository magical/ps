package main

import (
	"flag"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	pid := flag.Int("p", 0, "pid to scan [default: all]")
	flag.Parse()
	if *pid != 0 {
		if err := printModules(uint32(*pid)); err != nil {
			fmt.Println(err)
		}
		if err := printThreads(uint32(*pid)); err != nil {
			fmt.Println(err)
		}
	} else {
		listProcesses()
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

func listProcesses() {
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
	fmt.Println("Modules:")
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

func printThreads(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	fmt.Println("Threads:")
	var thread ThreadEntry32
	thread.Size = uint32(unsafe.Sizeof(thread))
	for err = Thread32First(snapshot, &thread); err == nil; err = Thread32Next(snapshot, &thread) {
		/*h, err := windows.OpenThread(thread.ThreadID)
		if err != nil {
			fmt.Println("OpenThread(%d): %v\n",thread.ThreadID, err)
			continue
		}
		*/
		if thread.OwnerProcessID == pid {
			fmt.Printf("\t%d\n", thread.ThreadID)
		}
	}
	if err == windows.ERROR_NO_MORE_FILES {
		return nil
	}
	return err
}
