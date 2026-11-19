package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cyberanchor/GoPassGen/internal/derive"
	"github.com/cyberanchor/GoPassGen/internal/logx"
	"github.com/cyberanchor/GoPassGen/internal/passgen"
)

var errDiskFull = errors.New("no space left on device")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errDiskFull }

// blockingWriter behaves like a pipe nobody reads.
type blockingWriter struct{ release chan struct{} }

func (w blockingWriter) Write(p []byte) (int, error) {
	<-w.release
	return len(p), nil
}

// blockingReader behaves like a terminal or pipe with no input yet.
type blockingReader struct{ release chan struct{} }

func (r blockingReader) Read([]byte) (int, error) {
	<-r.release
	return 0, io.EOF
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestStdoutWriteFailureIsReported(t *testing.T) {
	cases := [][]string{{"-version"}, {"-mnemonic-only"}, {"-mnemonic-only", "-count", "1000"}}
	if !testing.Short() {
		cases = append(cases, []string{"-self-test"}, []string{"-mnemonic", validEN}, []string{"-auto-gen"})
	}
	for _, args := range cases {
		var errb bytes.Buffer
		code := RunContext(context.Background(), args, strings.NewReader(""), failingWriter{}, &errb)
		if code != 1 {
			t.Errorf("%v: exit = %d, want 1", args, code)
		}
		if !strings.Contains(errb.String(), "no space left") {
			t.Errorf("%v: stderr = %q", args, errb.String())
		}
	}
}

func TestSelfTestFailureIsReported(t *testing.T) {
	runSelfTests = func(context.Context) ([]passgen.SelfTestResult, error) {
		results := []passgen.SelfTestResult{{Name: "kdf", Detail: "wrong answer"}}
		return results, errors.New("self-test failed: [kdf]")
	}
	defer func() { runSelfTests = passgen.SelfTestContext }()

	r := exec(t, "-self-test")
	if r.code != 1 {
		t.Errorf("exit = %d, want 1", r.code)
	}
	if !strings.Contains(r.stdout, "FAIL kdf") || strings.Contains(r.stdout, "checks passed") {
		t.Errorf("stdout = %q", r.stdout)
	}
	if !strings.Contains(r.stderr, "self-test failed") {
		t.Errorf("stderr = %q", r.stderr)
	}
}

// TestOutputBuffersAreErased covers the sink buffer and the copies made for
// writing, both while streaming and while holding data for an in-place overwrite.
func TestOutputBuffersAreErased(t *testing.T) {
	var tracked [][]byte
	derive.SecretHook = func(b []byte) { tracked = append(tracked, b) }
	defer func() { derive.SecretHook = nil }()

	path := filepath.Join(t.TempDir(), "out.txt")
	if r := exec(t, "-mnemonic-only", "-count", "1000", "-words", "24", "-output", path); r.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	if r := exec(t, "-mnemonic-only", "-count", "1000", "-words", "24"); r.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	if len(tracked) == 0 {
		t.Fatal("nothing was tracked")
	}
	for i, b := range tracked {
		if strings.Trim(string(b[:cap(b)]), "\x00") != "" {
			t.Errorf("tracked buffer %d (%d bytes) was not erased", i, cap(b))
		}
	}
}

func TestFullDeviceIsReported(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("/dev/full is not available")
	}
	cases := [][]string{{"-mnemonic-only", "-count", "3"}}
	if !testing.Short() {
		cases = append(cases, []string{"-auto-gen"}, []string{"-mnemonic", validEN})
	}
	for _, args := range cases {
		r := exec(t, append(args, "-output", "/dev/full")...)
		if r.code != 1 {
			t.Errorf("%v: exit = %d, want 1", args, r.code)
		}
		if strings.Contains(r.stderr, "wrote") {
			t.Errorf("%v: success reported:\n%s", args, r.stderr)
		}
	}
}

func testOptions(path string) *options {
	return &options{output: path, set: map[string]bool{"output": true}}
}

func TestFailedWriteKeepsExistingFileAndLeavesNoTrace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "phrases.txt")
	writeFile(t, path, "precious\n", 0o644)

	s, err := openSink(context.Background(), testOptions(path), io.Discard, logx.Discard())
	if err != nil {
		t.Fatal(err)
	}
	s.dst = failingWriter{}
	s.writeString("new data\n")
	err = s.commit()
	s.abort()
	if !errors.Is(err, errDiskFull) {
		t.Fatalf("commit error = %v", err)
	}
	if got := readFile(t, path); got != "precious\n" {
		t.Errorf("existing file changed to %q", got)
	}
	if names := listDir(t, dir); len(names) != 1 {
		t.Errorf("left behind: %v", names)
	}
}

func TestFailedSyncKeepsExistingFile(t *testing.T) {
	syncOutput = func(*os.File) error { return errDiskFull }
	defer func() { syncOutput = syncFile }()

	dir := t.TempDir()
	path := filepath.Join(dir, "phrases.txt")
	writeFile(t, path, "precious\n", 0o644)
	r := exec(t, "-mnemonic-only", "-output", path)
	if r.code != 1 || strings.Contains(r.stderr, "wrote") {
		t.Errorf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	if got := readFile(t, path); got != "precious\n" {
		t.Errorf("existing file changed to %q", got)
	}
	if names := listDir(t, dir); len(names) != 1 {
		t.Errorf("left behind: %v", names)
	}
}

func TestNothingAppearsBeforeCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	s, err := openSink(context.Background(), testOptions(path), io.Discard, logx.Discard())
	if err != nil {
		t.Fatal(err)
	}
	defer s.abort()
	s.writeString(strings.Repeat("x", 3*sinkBufferSize))
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("target visible before commit: %v", err)
	}
	if err := s.commit(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); len(got) != 3*sinkBufferSize {
		t.Errorf("file has %d bytes", len(got))
	}
	if names := listDir(t, dir); len(names) != 1 {
		t.Errorf("temporary file left behind: %v", names)
	}
}

func TestFailedRenameKeepsTheNewData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	s, err := openSink(context.Background(), testOptions(path), io.Discard, logx.Discard())
	if err != nil {
		t.Fatal(err)
	}
	s.writeString("irreplaceable\n")
	if err := os.Mkdir(path, 0o755); err != nil { // the target becomes impossible to replace
		t.Fatal(err)
	}
	err = s.commit()
	s.abort()
	if err == nil {
		t.Fatal("commit reported success")
	}
	tmp := s.file.tmp
	if !strings.Contains(err.Error(), filepath.Base(tmp)) {
		t.Errorf("error %q does not say where the data is", err)
	}
	if got := readFile(t, tmp); got != "irreplaceable\n" {
		t.Errorf("kept file holds %q", got)
	}
}

func TestInterruptedRunKeepsExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "phrases.txt")
	writeFile(t, path, "precious\n", 0o644)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := RunContext(ctx, []string{"-mnemonic-only", "-count", "100", "-output", path}, strings.NewReader(""), &out, &errb)
	if code != 130 {
		t.Fatalf("exit = %d, stderr = %s", code, errb.String())
	}
	if got := readFile(t, path); got != "precious\n" {
		t.Errorf("existing file changed to %q", got)
	}
	if names := listDir(t, dir); len(names) != 1 {
		t.Errorf("left behind: %v", names)
	}
}

func TestFailedRunRemovesDirectoriesItCreated(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	path := filepath.Join(root, "a", "b", "c", "out.txt")
	if code := RunContext(ctx, []string{"-mnemonic-only", "-output", path}, strings.NewReader(""), &out, &errb); code != 130 {
		t.Fatalf("exit = %d, stderr = %s", code, errb.String())
	}
	if names := listDir(t, root); len(names) != 0 {
		t.Errorf("left behind: %v", names)
	}
}

func TestDirectoriesAreCreatedForNewFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "out.txt")
	if r := exec(t, "-mnemonic-only", "-output", path); r.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	if strings.Count(readFile(t, path), "\n") != 1 {
		t.Error("file content is wrong")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o700 != 0o700 {
			t.Errorf("directory mode %v", info.Mode().Perm())
		}
	}
}

func TestPathNamingADirectoryIsRejectedWithoutSideEffects(t *testing.T) {
	root := t.TempDir()
	sep := string(filepath.Separator)
	for _, path := range []string{
		root + sep + "new" + sep,
		root + sep + "new" + sep + ".",
		root + sep + "new" + sep + "..",
		".", "..", sep,
	} {
		r := exec(t, "-mnemonic-only", "-output", path)
		if r.code != 1 || !strings.Contains(r.stderr, "directory") {
			t.Errorf("%q: exit = %d, stderr = %q", path, r.code, r.stderr)
		}
	}
	if names := listDir(t, root); len(names) != 0 {
		t.Errorf("created: %v", names)
	}
}

func TestBadOutputFailsBeforeAnyDerivation(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	writeFile(t, blocker, "", 0o644)
	bad := filepath.Join(blocker, "child")

	start := time.Now()
	r := exec(t, "-auto-gen", "-phrases", "100", "-output", bad)
	if r.code != 1 || r.stdout != "" {
		t.Errorf("-auto-gen: exit = %d, stdout = %q", r.code, r.stdout)
	}
	r = execStdin(t, validEN, "-mnemonic-stdin", "-output", bad)
	if r.code != 1 || r.stdout != "" {
		t.Errorf("-mnemonic-stdin: exit = %d, stdout = %q", r.code, r.stdout)
	}
	// 100 derivations take most of a minute; failing first takes milliseconds.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v, the derivations seem to run first", elapsed)
	}
}

func TestSingleModeHonoursOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("1,000,000 PBKDF2 iterations")
	}
	path := filepath.Join(t.TempDir(), "password.txt")
	r := exec(t, "-mnemonic", validEN, "-output", path)
	if r.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	if r.stdout != "" {
		t.Errorf("the password also went to stdout: %q", r.stdout)
	}
	if got := readFile(t, path); got != validENPassword12+"\n" {
		t.Errorf("file holds %q", got)
	}
	if !strings.Contains(r.stderr, "wrote password") {
		t.Errorf("stderr = %s", r.stderr)
	}
}

func TestAutoGenWithOutputKeepsSecretsOffStdout(t *testing.T) {
	if testing.Short() {
		t.Skip("PBKDF2 runs")
	}
	path := filepath.Join(t.TempDir(), "pairs.txt")
	r := exec(t, "-auto-gen", "-output", path)
	if r.code != 0 || r.stdout != "" {
		t.Errorf("exit = %d, stdout = %q", r.code, r.stdout)
	}
	if strings.Count(readFile(t, path), "\n") != 2 {
		t.Error("the file should hold one mnemonic and one password")
	}
}

func TestPathIsHiddenWithCaseSensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "my-secret-name.txt")
	writeFile(t, path, "old", 0o644)
	bad := filepath.Join(path, "child")

	for _, c := range []struct {
		args []string
		code int
	}{
		{[]string{"-mnemonic-only", "-output", path}, 0},
		{[]string{"-mnemonic-only", "-output", bad}, 1},
		{[]string{"-mnemonic-only", "-output", dir}, 1},
	} {
		plain := exec(t, c.args...)
		if plain.code != c.code || !strings.Contains(plain.stderr, "my-secret-name") && c.args[2] != dir {
			t.Errorf("%v without the flag: exit = %d, stderr = %s", c.args, plain.code, plain.stderr)
		}
		r := exec(t, append(c.args, "-case-sensitive")...)
		if r.code != c.code {
			t.Errorf("%v: exit = %d, want %d", c.args, r.code, c.code)
		}
		if strings.Contains(r.stderr, "my-secret-name") || strings.Contains(r.stderr, dir) {
			t.Errorf("%v: path leaked:\n%s", c.args, r.stderr)
		}
		if !strings.Contains(r.stderr, "<hidden>") {
			t.Errorf("%v: stderr = %s", c.args, r.stderr)
		}
	}
}

func TestBlockedStdinCanBeInterrupted(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	assertInterrupted(t, []string{"-mnemonic-stdin"}, blockingReader{release}, io.Discard)
}

func TestBlockedStdoutCanBeInterrupted(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	w := blockingWriter{release}
	assertInterrupted(t, []string{"-mnemonic-only"}, strings.NewReader(""), w)
	assertInterrupted(t, []string{"-version"}, strings.NewReader(""), w)
}

func TestDerivationCanBeInterrupted(t *testing.T) {
	assertInterrupted(t, []string{"-mnemonic", validEN}, strings.NewReader(""), io.Discard)
	assertInterrupted(t, []string{"-self-test"}, strings.NewReader(""), io.Discard)
}

func assertInterrupted(t *testing.T, args []string, stdin io.Reader, stdout io.Writer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	var errb bytes.Buffer
	go func() { done <- RunContext(ctx, args, stdin, stdout, &errb) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case code := <-done:
		if code != 130 {
			t.Errorf("%v: exit = %d, want 130\n%s", args, code, errb.String())
		}
		if !strings.Contains(errb.String(), "interrupted") {
			t.Errorf("%v: stderr = %s", args, errb.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("%v: still running long after the cancellation", args)
	}
}

func TestReadMnemonicLineStopsAtNewline(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"phrase\nignored", "phrase", false},
		{"phrase\r\n", "phrase", false},
		{"phrase", "phrase", false},
		{"\n", "", true},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := readMnemonicLine(strings.NewReader(c.in))
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("%q: got %q, err = %v", c.in, got, err)
		}
	}
}

func TestReadErrorsAreReported(t *testing.T) {
	broken := io.MultiReader(strings.NewReader("abandon"), iotestErrReader{})
	if _, err := readMnemonic(broken); !errors.Is(err, errDiskFull) {
		t.Errorf("readMnemonic: err = %v", err)
	}
	if _, err := readMnemonicLine(iotestErrReader{}); !errors.Is(err, errDiskFull) {
		t.Errorf("readMnemonicLine: err = %v", err)
	}
}

type iotestErrReader struct{}

func (iotestErrReader) Read([]byte) (int, error) { return 0, errDiskFull }
