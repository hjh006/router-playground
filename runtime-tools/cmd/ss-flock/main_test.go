package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("TEST_SS_FLOCK_HELPER") != "1" {
		return
	}
	if os.Getenv("TEST_SS_FLOCK_READY") == "1" {
		ready := os.NewFile(4, "ready")
		io.WriteString(ready, "ready")
		ready.Close()
	}
	for index, arg := range os.Args {
		if arg == "--" {
			os.Exit(run(os.Args[index+1:]))
		}
	}
	os.Exit(2)
}

func helper(file *os.File, args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestHelperProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "TEST_SS_FLOCK_HELPER=1")
	if file != nil {
		cmd.ExtraFiles = []*os.File{file}
	}
	return cmd
}

func expectExit(t *testing.T, cmd *exec.Cmd, want int) {
	t.Helper()
	output, err := cmd.CombinedOutput()
	got := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			got = exit.ExitCode()
		} else {
			t.Fatalf("could not execute helper: %v", err)
		}
	}
	if got != want {
		t.Fatalf("exit=%d want=%d: %s", got, want, output)
	}
}

func openLock(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	return file
}

func TestInheritedLockPersistsAndSharedUnlockReleases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	owner := openLock(t, path)
	competitor := openLock(t, path)
	expectExit(t, helper(owner, "-n", "3"), 0)
	if _, err := owner.Stat(); err != nil {
		t.Fatalf("caller descriptor was closed: %v", err)
	}
	expectExit(t, helper(competitor, "-n", "3"), 1)
	expectExit(t, helper(owner, "-u", "3"), 0)
	expectExit(t, helper(competitor, "-n", "3"), 0)
	expectExit(t, helper(competitor, "-u", "3"), 0)
}

func TestBlockingExclusiveWaitsForUnlock(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "bare"
		if explicit {
			name = "explicit-x"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lock")
			owner := openLock(t, path)
			competitor := openLock(t, path)
			expectExit(t, helper(owner, "-n", "3"), 0)
			args := []string{"3"}
			if explicit {
				args = []string{"-x", "3"}
			}
			cmd := helper(competitor, args...)
			readReady, writeReady, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer readReady.Close()
			cmd.ExtraFiles = append(cmd.ExtraFiles, writeReady)
			cmd.Env = append(cmd.Env, "TEST_SS_FLOCK_READY=1")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			writeReady.Close()
			t.Cleanup(func() { cmd.Process.Kill() })
			if _, err := io.ReadFull(readReady, make([]byte, 5)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				t.Fatalf("blocking lock returned while owner holds it: %v", err)
			case <-time.After(80 * time.Millisecond):
			}
			expectExit(t, helper(owner, "-u", "3"), 0)
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("blocking lock did not resume after unlock")
			}
			expectExit(t, helper(owner, "-n", "3"), 1)
			expectExit(t, helper(competitor, "-u", "3"), 0)
		})
	}
}

func TestRejectsPathsCommandsAndInvalidDescriptors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "must-not-create")
	for _, args := range [][]string{nil, {path}, {"-n"}, {"-z", "3"}, {"-1"}, {"2147483648"}, {"3", "echo", "unexpected"}, {"-n", "2147483647"}} {
		expectExit(t, helper(nil, args...), 2)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("path argument caused filesystem access")
	}
}
