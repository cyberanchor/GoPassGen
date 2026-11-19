package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cyberanchor/GoPassGen/internal/derive"
)

const (
	// outputFileMode gives new files ordinary permissions; the umask narrows it.
	outputFileMode fs.FileMode = 0o644
	outputDirMode  fs.FileMode = 0o755

	sinkBufferSize = 64 * 1024
)

var (
	errOutputSymlink = errors.New("it is a symbolic link, refusing to write through it")
	errOutputIsDir   = errors.New("it is a directory")
	errOutputChanged = errors.New("it changed while it was being opened")

	// syncOutput is replaced by tests, since a real fsync failure cannot be
	// provoked on demand.
	syncOutput = syncFile
)

// outputError is an I/O failure on the -output file. The message never contains
// the path: RunContext logs it as a separate attribute, which is the one place
// that has to know about -case-sensitive.
type outputError struct {
	op  string
	err error
}

func (e *outputError) Error() string { return e.op + ": " + e.err.Error() }
func (e *outputError) Unwrap() error { return e.err }

// withoutPath strips the file name that os errors carry.
func withoutPath(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return linkErr.Err
	}
	return err
}

func outputFailure(op string, err error) error {
	return &outputError{op: op, err: withoutPath(err)}
}

// contextWriter stops waiting for a blocked destination, such as a full pipe,
// when ctx is cancelled. The write runs on its own copy of the data in a
// goroutine that is abandoned on cancellation.
type contextWriter struct {
	ctx context.Context
	w   io.Writer
}

func (c contextWriter) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	type result struct {
		n   int
		err error
	}
	data := derive.TrackSecret(append([]byte(nil), p...))
	done := make(chan result, 1)
	go func() {
		n, err := c.w.Write(data)
		derive.Wipe(data)
		done <- result{n, err}
	}()
	select {
	case r := <-done:
		return r.n, r.err
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}
}

// writeText writes non-secret text to stdout.
func writeText(w io.Writer, text string) error {
	if _, err := io.WriteString(w, text); err != nil {
		if isCancellation(err) {
			return err
		}
		return fmt.Errorf("writing output: %w", withoutPath(err))
	}
	return nil
}

func isCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// sink receives generated secrets. Data is buffered, abort erases the buffer, and
// nothing counts as written until commit has succeeded: a write, sync or rename
// failure is reported there instead of being lost.
//
// Write errors are sticky, like those of bufio.Writer, so callers can make
// several writes and check once.
type sink struct {
	dst       io.Writer
	buf       []byte
	file      *outputFile // nil when writing to stdout
	err       error
	committed bool
}

// openSink prepares the destination: stdout, or the -output file. All problems
// with the file surface here, before any work is done.
func openSink(ctx context.Context, opts *options, stdout io.Writer, log *slog.Logger) (*sink, error) {
	s := &sink{dst: stdout, buf: derive.TrackSecret(make([]byte, 0, sinkBufferSize))}
	if opts.output == "" {
		return s, nil
	}
	file, err := openOutput(ctx, opts.output)
	if err != nil {
		return nil, err
	}
	s.file = file
	s.dst = contextWriter{ctx: ctx, w: file.f}
	if file.replacing {
		log.Warn("output file already exists and will be replaced when this run succeeds", opts.pathAttr())
	}
	return s, nil
}

func (s *sink) write(p []byte) {
	for len(p) > 0 && s.err == nil {
		if len(s.buf) == cap(s.buf) {
			s.makeRoom()
		}
		n := copy(s.buf[len(s.buf):cap(s.buf)], p)
		s.buf = s.buf[:len(s.buf)+n]
		p = p[n:]
	}
}

func (s *sink) writeString(text string) {
	for len(text) > 0 && s.err == nil {
		if len(s.buf) == cap(s.buf) {
			s.makeRoom()
		}
		n := copy(s.buf[len(s.buf):cap(s.buf)], text)
		s.buf = s.buf[:len(s.buf)+n]
		text = text[n:]
	}
}

// makeRoom flushes a full buffer. A file overwritten in place is the exception:
// it keeps its old contents until commit, so the data has to stay in memory.
func (s *sink) makeRoom() {
	if s.file == nil || !s.file.inPlace {
		s.flush()
		return
	}
	bigger := derive.TrackSecret(make([]byte, len(s.buf), 2*cap(s.buf)))
	copy(bigger, s.buf)
	derive.Wipe(s.buf)
	s.buf = bigger
}

func (s *sink) flush() {
	if s.err != nil || len(s.buf) == 0 {
		return
	}
	_, err := s.dst.Write(s.buf)
	s.buf = s.buf[:0]
	switch {
	case err == nil:
	case isCancellation(err):
		s.err = err
	case s.file != nil:
		s.err = outputFailure("writing output file", err)
	default:
		s.err = fmt.Errorf("writing output: %w", withoutPath(err))
	}
}

// commit makes the output final and reports any failure on the way there.
func (s *sink) commit() error {
	if s.file != nil && s.file.inPlace && s.err == nil {
		if err := s.file.f.Truncate(0); err != nil {
			s.err = outputFailure("writing output file", err)
		}
	}
	s.flush()
	if s.err != nil {
		return s.err
	}
	if s.file != nil {
		if err := s.file.commit(); err != nil {
			s.err = err
			return err
		}
	}
	s.committed = true
	return nil
}

// abort erases the buffer and, unless commit succeeded, removes what the run
// created. Any file that already existed is left as it was.
func (s *sink) abort() {
	derive.Wipe(s.buf[:cap(s.buf)])
	s.buf = s.buf[:0]
	if s.file != nil && !s.committed {
		s.file.discard()
	}
}

// outputFile is an open -output destination.
//
// A regular file is written through a temporary file in the same directory and
// renamed over the target only after everything has been written and synced. A
// full disk or Ctrl-C therefore never damages an existing file, and the rename
// replaces whatever is at the path without following a link planted there.
type outputFile struct {
	path        string
	f           *os.File
	tmp         string   // temporary file; empty when writing to path directly
	keepTmp     bool     // the rename failed, so tmp holds the only copy
	inPlace     bool     // existing file overwritten directly at commit
	replacing   bool     // a regular file already exists at path
	createdDirs []string // directories this run created, deepest first
}

func openOutput(ctx context.Context, path string) (*outputFile, error) {
	const opening = "opening output file"

	base := filepath.Base(path)
	if strings.HasSuffix(path, "/") || strings.HasSuffix(path, string(filepath.Separator)) ||
		base == "." || base == ".." || base == string(filepath.Separator) {
		return nil, outputFailure(opening, errOutputIsDir)
	}

	info, err := os.Lstat(path)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, outputFailure(opening, err)
	}

	var existing *os.File
	mode := outputFileMode
	if exists {
		switch m := info.Mode(); {
		case m&os.ModeSymlink != 0:
			// A link to a pipe or device is fine: /dev/fd/N from >(command)
			// is one, and nothing can be overwritten through it.
			if target, err := os.Stat(path); err == nil && !target.Mode().IsRegular() && !target.IsDir() {
				return openSpecial(ctx, path)
			}
			return nil, outputFailure(opening, errOutputSymlink)
		case m.IsDir():
			return nil, outputFailure(opening, errOutputIsDir)
		case !m.IsRegular():
			return openSpecial(ctx, path)
		}
		// Without O_TRUNC this only proves the file is writable, so a read-only
		// file is respected even though a rename could replace it.
		existing, err = os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return nil, outputFailure(opening, err)
		}
		// The open follows links, so make sure it reached the file examined above.
		if opened, err := existing.Stat(); err != nil || !os.SameFile(info, opened) {
			_ = existing.Close()
			return nil, outputFailure(opening, errOutputChanged)
		}
		mode = info.Mode().Perm()
	}

	o := &outputFile{path: path, replacing: exists}
	dir := filepath.Dir(path)
	if !exists {
		o.createdDirs, err = createParents(dir)
		if err != nil {
			return nil, outputFailure("creating directory for output file", err)
		}
	}

	f, tmp, err := createTemp(dir, mode)
	switch {
	case err == nil:
	case exists && errors.Is(err, fs.ErrPermission):
		// The file may be written but its directory may not, as with a file
		// mounted into a container.
		o.f, o.inPlace = existing, true
		return o, nil
	default:
		if existing != nil {
			_ = existing.Close()
		}
		o.discard()
		return nil, outputFailure(opening, err)
	}
	o.f, o.tmp = f, tmp

	if exists {
		_ = existing.Close()
		// The umask must not change the mode of a file that is being replaced.
		if err := f.Chmod(mode); err != nil {
			o.discard()
			return nil, outputFailure(opening, err)
		}
		copyOwner(f, info)
	}
	return o, nil
}

// openSpecial opens a device, pipe or similar. Opening a FIFO blocks until a
// reader appears, so it must not prevent cancellation.
func openSpecial(ctx context.Context, path string) (*outputFile, error) {
	const opening = "opening output file"
	type result struct {
		f   *os.File
		err error
	}
	done := make(chan result, 1)
	go func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		done <- result{f, err}
	}()

	var r result
	select {
	case r = <-done:
	case <-ctx.Done():
		go func() {
			if late := <-done; late.f != nil {
				_ = late.f.Close()
			}
		}()
		return nil, ctx.Err()
	}
	if r.err != nil {
		return nil, outputFailure(opening, r.err)
	}
	// The path could have been swapped since it was examined.
	if info, err := r.f.Stat(); err != nil || info.Mode().IsRegular() {
		_ = r.f.Close()
		return nil, outputFailure(opening, errOutputChanged)
	}
	return &outputFile{path: path, f: r.f}, nil
}

// createParents creates dir and returns the directories that did not exist,
// deepest first, so a failed run can remove exactly those.
func createParents(dir string) ([]string, error) {
	var missing []string
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		missing = append(missing, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	if err := os.MkdirAll(dir, outputDirMode); err != nil {
		removeDirs(missing)
		return nil, err
	}
	return missing, nil
}

// removeDirs removes directories until one is not empty or cannot be removed.
func removeDirs(dirs []string) {
	for _, d := range dirs {
		if os.Remove(d) != nil && !isNotExist(d) {
			return
		}
	}
}

func isNotExist(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, fs.ErrNotExist)
}

func createTemp(dir string, mode fs.FileMode) (*os.File, string, error) {
	for attempt := 0; ; attempt++ {
		var id [8]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, "", err
		}
		// O_EXCL neither reuses an existing file nor follows a link.
		name := filepath.Join(dir, ".gopassgen-"+hex.EncodeToString(id[:])+".tmp")
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if errors.Is(err, fs.ErrExist) && attempt < 16 {
			continue
		}
		return f, name, err
	}
}

// commit publishes data already written to o.f.
func (o *outputFile) commit() error {
	const writing = "writing output file"

	f := o.f
	o.f = nil
	var err error
	if o.tmp != "" || o.inPlace {
		err = syncOutput(f)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return outputFailure(writing, err)
	}
	if o.tmp == "" {
		return nil
	}

	if err := os.Rename(o.tmp, o.path); err != nil {
		// These may be phrases that exist nowhere else, so they are kept.
		o.keepTmp = true
		return outputFailure("replacing output file, the new data is in "+filepath.Base(o.tmp), err)
	}
	o.tmp = ""
	syncDir(filepath.Dir(o.path))
	return nil
}

// discard closes the file and removes what this run created.
func (o *outputFile) discard() {
	if o.f != nil {
		_ = o.f.Close()
		o.f = nil
	}
	if o.tmp != "" && !o.keepTmp {
		_ = os.Remove(o.tmp)
	}
	removeDirs(o.createdDirs)
}

// syncFile flushes f to stable storage. A file system that does not implement
// fsync is not an error; a failed fsync is.
func syncFile(f *os.File) error {
	err := f.Sync()
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		return nil
	}
	return err
}

// syncDir makes a rename durable where the platform allows it. Directories
// cannot be synced everywhere, and the data itself is already safe.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
