package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func usage() {
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("If no process id is specified, ps outputs a list of")
	fmt.Println("all processes and modules.")
	fmt.Println()
	fmt.Println("If a process id is specified, ps outputs the modules,")
	fmt.Println("thread IDs, and mapped pages of memory for that process.")
	fmt.Println()
	fmt.Println("If the -addr option is given then -p must be given as well;")
	fmt.Println("and ps will attempt to read a single word of memory from")
	fmt.Println("that address in the given process.")
	fmt.Println()
	os.Exit(1)
}

func main() {
	pid := flag.Int("p", 0, "pid to scan [default: all]")
	addr := flag.Uint64("addr", 0, "address to read from")
	flag.Usage = usage
	flag.Parse()
	if *addr != 0 {
		if *pid == 0 {
			fmt.Fprintln(os.Stderr, "error: -addr given without -p")
			os.Exit(1)
		}
		if err := printMemoryWord(*pid, *addr); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	} else if *pid != 0 {
		if err := printModules(uint32(*pid)); err != nil {
			fmt.Fprintln(os.Stderr, err)
		} else if err := printThreads(uint32(*pid)); err != nil {
			fmt.Fprintln(os.Stderr, err)
		} else if err := printVirtualMemoryPID(uint32(*pid)); err != nil {
			fmt.Fprintln(os.Stderr, err)
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

func printVirtualMemoryPID(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)
	if err != nil {
		return &SyscallError{"OpenProcess", err}
	}
	defer windows.CloseHandle(h)
	return printVirtualMemory(h)
}

func printVirtualMemory(h windows.Handle) error {
	fmt.Println("Virtual memory:")
	var address uintptr = 0
	var info MemoryBasicInfo
	for address = 0; ; address = info.BaseAddress + info.RegionSize {
		err := VirtualQueryEx(h, address, &info)
		if err != nil {
			if err == syscall.Errno(87) {
				return nil
			}
			return err
		}
		if info.State == MEM_FREE {
			continue
		}
		fmt.Printf("\t%08x-%08x size: % 8x state: %-10s type: %-10s protect: %s\n",
			info.BaseAddress,
			info.BaseAddress+info.RegionSize,
			info.RegionSize,
			stateName(info.State),
			typeName(info.Type),
			protectName(info.Protect),
		)
	}
}

func typeName(state uint32) string {
	switch state {
	case 0:
		return ""
	case MEM_IMAGE:
		return "image"
	case MEM_MAPPED:
		return "mapped"
	case MEM_PRIVATE:
		return "private"
	default:
		return fmt.Sprintf("unknown (%x)", state)
	}
}

func stateName(state uint32) string {
	switch state {
	case 0:
		return ""
	case MEM_FREE:
		return "free"
	case MEM_COMMIT:
		return "commit"
	case MEM_RESERVE:
		return "reserve"
	default:
		return fmt.Sprintf("unknown (%x)", state)
	}
}

func protectName(protect uint32) string {
	if protect == 0 {
		return ""
	}
	mod := " "
	if protect&0x100 != 0 {
		mod = "g"
	}
	switch protect & 0xff {
	case 0x1:
		return mod + "---"
	case 0x2:
		return mod + "r--"
	case 0x4:
		return mod + "rw-"
	case 0x8:
		return mod + "rc-"
	case 0x10:
		return mod + "--x"
	case 0x20:
		return mod + "r-x"
	case 0x40:
		return mod + "rwx"
	case 0x80:
		return mod + "rcx"
	default:
		return fmt.Sprintf("unknown (%x)", protect)
	}
}

func printMemoryWord(pid int, addr uint64) error {
	if pid < 1 {
		return fmt.Errorf("invalid pid: %d", pid)
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return &SyscallError{"OpenProcess", err}
	}
	defer windows.CloseHandle(h)

	var buf [4]byte
	var nread uintptr
	if err := ReadProcessMemory(h, uintptr(addr), &buf[0], 4, &nread); err != nil {
		return err
	}
	if nread != 4 {
		return fmt.Errorf("read failed")
	}
	word := binary.LittleEndian.Uint32(buf[:])
	fmt.Printf("%08x", word)
	return nil
}
