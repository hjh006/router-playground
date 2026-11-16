package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "mktemp":
			path, err := makeTemp(args[1:])
			if err != nil {
				fmt.Fprintln(os.Stderr, "ss-flock mktemp:", err)
				return 2
			}
			fmt.Println(path)
			return 0
		case "mode":
			if len(args) != 2 {
				return usage()
			}
			mode, err := pathMode(args[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "ss-flock mode:", err)
				return 2
			}
			fmt.Printf("%o\n", mode)
			return 0
		}
	}
	operation := syscall.LOCK_EX
	var descriptor string
	switch len(args) {
	case 1:
		descriptor = args[0]
	case 2:
		descriptor = args[1]
		switch args[0] {
		case "-x":
		case "-n":
			operation |= syscall.LOCK_NB
		case "-u":
			operation = syscall.LOCK_UN
		default:
			return usage()
		}
	default:
		return usage()
	}
	fd, err := strconv.ParseUint(descriptor, 10, 31)
	if err != nil {
		return usage()
	}
	for {
		err = syscall.Flock(int(fd), operation)
		if err != syscall.EINTR {
			break
		}
	}
	if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ss-flock: %v\n", err)
		return 2
	}
	return 0
}

func makeTemp(args []string) (string, error) {
	directory := false
	if len(args) > 0 && args[0] == "-d" {
		directory = true
		args = args[1:]
	}
	if len(args) != 1 || !strings.HasSuffix(args[0], "XXXXXX") || strings.ContainsAny(args[0], "\r\n\x00") {
		return "", fmt.Errorf("expected TEMPLATE ending in XXXXXX")
	}
	template := args[0]
	pattern := strings.TrimSuffix(filepath.Base(template), "XXXXXX") + "*"
	if directory {
		return os.MkdirTemp(filepath.Dir(template), pattern)
	}
	file, err := os.CreateTemp(filepath.Dir(template), pattern)
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func pathMode(path string) (uint32, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("symbolic links are not supported")
	}
	mode := uint32(info.Mode().Perm())
	for _, special := range []struct {
		flag os.FileMode
		bit  uint32
	}{{os.ModeSetuid, 04000}, {os.ModeSetgid, 02000}, {os.ModeSticky, 01000}} {
		if info.Mode()&special.flag != 0 {
			mode |= special.bit
		}
	}
	return mode, nil
}

func usage() int {
	fmt.Fprintln(os.Stderr, "usage: ss-flock [-x|-n|-u] FD (inherited descriptor only)")
	fmt.Fprintln(os.Stderr, "       ss-flock mktemp [-d] TEMPLATE | mode PATH")
	return 2
}

func main() { os.Exit(run(os.Args[1:])) }
