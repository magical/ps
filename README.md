ps
====

`ps` is a small program which demonstrates how to use the Windows API to
enumerate and inspect processes.

`ps` was tested with Go 1.6 on Windows 10. It should work with any later version of Go. It will not work on operating systems other than Windows.

Installation
------------

    go install github.com/magical/ps

Installation, for people who have never used Go
------------

1. If you don't have Go installed, follow the [installation instructions][]
   to download and install Go.
   Be sure to set the GOPATH environment variable to some suitable directory before continuing.

2. Run `go install github.com/magical/ps` to download and build this `ps`.
   This command will clone this repository to `$GOPATH/src/github.com/magical/ps`,
   and download the `golang.org/x/sys` repository (which we depend on) to
   `$GOPATH/src/github.com/x/sys`.
   The `ps` binary will be installed to `$GOPATH/bin/ps`.

[installation instructions]: https://golang.org/doc/install

Examples
--------

    ps -help

Prints usage information for `ps`.

    ps

Prints a list of all processes (that the current user is allowed to access),
along with the list of modules (DLLs) in each process.

    ps -p 1234

Prints information about the process with PID 1234, including: modules, thread IDs, and a list of mapped virtual memory pages.

    ps -p 1234 -addr 0x77740000

Prints the DWORD at virtual address 0x77740000 in process 1234, assuming
that it is a valid address.
