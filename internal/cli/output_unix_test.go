//go:build unix

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cyberanchor/GoPassGen/internal/derive"
)

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission checks do not apply to root")
	}
}

func TestSymlinkIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	writeFile(t, victim, "untouched\n", 0o644)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "does-not-exist"), dangling); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{link, dangling} {
		r := exec(t, "-mnemonic-only", "-output", path)
		if r.code != 1 || !strings.Contains(r.stderr, "symbolic link") {
			t.Errorf("%s: exit = %d, stderr = %s", path, r.code, r.stderr)
		}
	}
	if got := readFile(t, victim); got != "untouched\n" {
		t.Errorf("the link target changed to %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "does-not-exist")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a file appeared behind the dangling link")
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link itself was replaced: %v", err)
	}
}

func TestReadOnlyFileIsRespected(t *testing.T) {
	skipIfRoot(t)
	path := filepath.Join(t.TempDir(), "locked.txt")
	writeFile(t, path, "keep\n", 0o400)
	r := exec(t, "-mnemonic-only", "-output", path)
	if r.code != 1 || !strings.Contains(r.stderr, "permission denied") {
		t.Errorf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	if got := readFile(t, path); got != "keep\n" {
		t.Errorf("file changed to %q", got)
	}
}

// TestNewFileModeWithoutUmask shows the mode itself, which a typical umask hides.
func TestNewFileModeWithoutUmask(t *testing.T) {
	defer syscall.Umask(syscall.Umask(0))
	path := filepath.Join(t.TempDir(), "out.txt")
	if r := exec(t, "-mnemonic-only", "-output", path); r.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o, want 644", info.Mode().Perm())
	}
}

func TestReplacedFileKeepsItsMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	for _, mode := range []os.FileMode{0o600, 0o640, 0o664} {
		writeFile(t, path, "old", 0o600)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if r := exec(t, "-mnemonic-only", "-output", path); r.code != 0 {
			t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("mode %o became %o", mode, info.Mode().Perm())
		}
	}
}

// TestFileInReadOnlyDirectoryIsOverwrittenAtTheEnd covers the case where no
// temporary file can be created next to the target.
func TestFileInReadOnlyDirectoryIsOverwrittenAtTheEnd(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	writeFile(t, path, "old\n", 0o644)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	// More data than one buffer, so it has to stay in memory until the end.
	r := exec(t, "-mnemonic-only", "-count", "1000", "-words", "24", "-output", path)
	if r.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	if got := strings.Count(readFile(t, path), "\n"); got != 1000 {
		t.Errorf("file has %d lines", got)
	}

	// New contents shorter than the old ones must not leave a tail behind. The
	// whole old line is searched for, because "gold" and "hold" are valid words.
	writeFile(t, path, strings.Repeat("old contents\n", 10_000), 0o644)
	if r := exec(t, "-mnemonic-only", "-output", path); r.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	if got := readFile(t, path); strings.Contains(got, "old contents") || strings.Count(got, "\n") != 1 {
		t.Errorf("file holds %d bytes after the overwrite", len(got))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	writeFile(t, path, "old\n", 0o644)
	var out, errb bytes.Buffer
	if code := RunContext(ctx, []string{"-mnemonic-only", "-output", path}, strings.NewReader(""), &out, &errb); code != 130 {
		t.Fatalf("exit = %d", code)
	}
	if got := readFile(t, path); got != "old\n" {
		t.Errorf("an interrupted run changed the file to %q", got)
	}
}

// TestBuffersOutgrownInMemoryAreErased: data for an in-place overwrite is held in
// a growing buffer, and each smaller predecessor contains the same secrets.
func TestBuffersOutgrownInMemoryAreErased(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	writeFile(t, path, "old\n", 0o644)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	var tracked [][]byte
	derive.SecretHook = func(b []byte) { tracked = append(tracked, b) }
	defer func() { derive.SecretHook = nil }()
	if r := exec(t, "-mnemonic-only", "-count", "1000", "-words", "24", "-output", path); r.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	sizes := map[int]bool{}
	for i, b := range tracked {
		sizes[cap(b)] = true
		if strings.Trim(string(b[:cap(b)]), "\x00") != "" {
			t.Errorf("tracked buffer %d (%d bytes) was not erased", i, cap(b))
		}
	}
	if !sizes[2*sinkBufferSize] {
		t.Errorf("the buffer never grew: sizes %v", sizes)
	}
}

func TestOutputToFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	received := make(chan string, 1)
	go func() {
		data, _ := os.ReadFile(fifo)
		received <- string(data)
	}()
	if r := exec(t, "-mnemonic-only", "-count", "2", "-output", fifo); r.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	select {
	case got := <-received:
		if strings.Count(got, "\n") != 2 {
			t.Errorf("reader got %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the reader got nothing")
	}
	if names := listDir(t, dir); len(names) != 1 {
		t.Errorf("left behind: %v", names)
	}
}

func TestSymlinkToFIFOIsAllowed(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	go os.ReadFile(fifo)
	if r := exec(t, "-mnemonic-only", "-output", link); r.code != 0 {
		t.Errorf("exit = %d, stderr = %s", r.code, r.stderr)
	}
}

func TestFIFOWithoutReaderCanBeInterrupted(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	assertInterrupted(t, []string{"-mnemonic-only", "-output", fifo}, strings.NewReader(""), io.Discard)
	// Let the abandoned open finish.
	if f, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
		f.Close()
	}
}
