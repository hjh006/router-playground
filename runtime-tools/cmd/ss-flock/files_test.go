package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestConcurrentTempCreationAndModes(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprint(directory), func(t *testing.T) {
			root := t.TempDir()
			template := filepath.Join(root, "prefix.XXXXXX")
			untouched := filepath.Join(root, "untouched")
			if err := os.WriteFile(untouched, []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(untouched, template); err != nil {
				t.Fatal(err)
			}
			const count = 64
			paths := make(chan string, count)
			errors := make(chan error, count)
			var group sync.WaitGroup
			for i := 0; i < count; i++ {
				group.Add(1)
				go func() {
					defer group.Done()
					args := []string{template}
					if directory {
						args = append([]string{"-d"}, args...)
					}
					path, err := makeTemp(args)
					if err != nil {
						errors <- err
						return
					}
					paths <- path
				}()
			}
			group.Wait()
			close(paths)
			close(errors)
			for err := range errors {
				t.Fatal(err)
			}
			seen := make(map[string]bool)
			for path := range paths {
				if seen[path] || filepath.Dir(path) != root || !strings.HasPrefix(filepath.Base(path), "prefix.") {
					t.Fatalf("duplicate or misplaced temporary path: %q", path)
				}
				seen[path] = true
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				wantMode := os.FileMode(0600)
				if directory {
					wantMode = 0700
				}
				if info.IsDir() != directory || info.Mode().Perm() != wantMode || info.Mode()&os.ModeSymlink != 0 {
					t.Fatalf("unsafe temporary entry: %s mode=%v", path, info.Mode())
				}
			}
			if len(seen) != count {
				t.Fatalf("created %d entries, want %d", len(seen), count)
			}
			if data, err := os.ReadFile(untouched); err != nil || string(data) != "preserve" {
				t.Fatal("pre-existing symbolic link target was modified")
			}
			if _, err := os.Readlink(template); err != nil {
				t.Fatal("pre-existing symbolic link was replaced")
			}
		})
	}
}

func TestTempRejectsInvalidTemplates(t *testing.T) {
	for _, args := range [][]string{nil, {"plain"}, {"fiveXXXXX"}, {"bad\nXXXXXX"}, {"-z", "XXXXXX"}, {"-d"}, {"XXXXXX", "extra"}} {
		if _, err := makeTemp(args); err == nil {
			t.Fatalf("invalid template accepted: %q", args)
		}
		expectExit(t, helper(nil, append([]string{"mktemp"}, args...)...), 2)
	}
}

func TestModeReportsUnixSpecialBitsAndRejectsSymlinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []struct {
		file os.FileMode
		unix uint32
	}{{0600, 0600}, {0400, 0400}, {0644, 0644}, {0755, 0755}, {0755 | os.ModeSetuid, 04755}, {0750 | os.ModeSetgid, 02750}, {0700 | os.ModeSticky, 01700}} {
		if err := os.Chmod(path, mode.file); err != nil {
			t.Fatal(err)
		}
		got, err := pathMode(path)
		if err != nil || got != mode.unix {
			t.Fatalf("mode=%o, err=%v; want %o", got, err, mode.unix)
		}
		output, err := helper(nil, "mode", path).Output()
		if err != nil || string(output) != fmt.Sprintf("%o\n", mode.unix) {
			t.Fatalf("mode CLI output=%q err=%v", output, err)
		}
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := pathMode(link); err == nil {
		t.Fatal("mode followed a symbolic link")
	}
	expectExit(t, helper(nil, "mode", link), 2)
	expectExit(t, helper(nil, "mode", path+".missing"), 2)
}

func TestTempCLIPrintsOnlyCreatedPath(t *testing.T) {
	for _, directory := range []bool{false, true} {
		args := []string{"mktemp"}
		if directory {
			args = append(args, "-d")
		}
		args = append(args, filepath.Join(t.TempDir(), "cli.XXXXXX"))
		output, err := helper(nil, args...).Output()
		if err != nil {
			t.Fatal(err)
		}
		path := strings.TrimSuffix(string(output), "\n")
		info, err := os.Lstat(path)
		if err != nil || info.IsDir() != directory || strings.ContainsAny(path, "\r\n") {
			t.Fatalf("invalid CLI temporary path: %q err=%v", output, err)
		}
		wantMode := "600\n"
		if directory {
			wantMode = "700\n"
		}
		modeOutput, err := helper(nil, "mode", path).Output()
		if err != nil || string(modeOutput) != wantMode {
			t.Fatalf("CLI mode=%q err=%v; want %q", modeOutput, err, wantMode)
		}
	}
}
