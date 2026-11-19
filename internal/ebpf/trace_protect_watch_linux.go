//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// imageWatchMask: a file appears (create, rename into place, a finished write),
// goes away or changes its attributes in a directory that holds a trusted
// image. A package upgrade replaces the binary by rename, and a restart may
// follow within milliseconds, so the 5 s refresh alone would miss the new
// file's identity at the first exec.
const imageWatchMask = unix.IN_CREATE | unix.IN_MOVED_TO | unix.IN_CLOSE_WRITE | unix.IN_ATTRIB |
	unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_ONLYDIR

// imageWatch reports on changed that a file which could be a trusted image
// changed on disk. The channel holds one signal: a burst of events is one
// refresh.
type imageWatch struct {
	f       *os.File
	changed chan struct{}
	exited  chan struct{}
}

// watchProtectedImages watches the directories of every path in imagePaths and
// signals for the basenames of those paths only. A directory that does not
// exist is skipped. Close the result when done.
func watchProtectedImages(s *ProtectedProcessSet) (*imageWatch, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify_init1: %w", err)
	}
	dirs := make(map[string]struct{})
	names := make(map[string]struct{})
	for p := range s.imagePaths() {
		dirs[filepath.Dir(p)] = struct{}{}
		names[filepath.Base(p)] = struct{}{}
	}
	watched := 0
	var errs []error
	for dir := range dirs {
		if _, err := unix.InotifyAddWatch(fd, dir, imageWatchMask); err != nil {
			if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTDIR) {
				errs = append(errs, fmt.Errorf("watch %s: %w", dir, err))
			}
			continue
		}
		watched++
	}
	if watched == 0 {
		_ = unix.Close(fd) // nothing was watched; the error below says why
		return nil, errors.Join(append(errs, errors.New("no directory to watch"))...)
	}
	w := &imageWatch{
		f:       os.NewFile(uintptr(fd), "inotify"),
		changed: make(chan struct{}, 1),
		exited:  make(chan struct{}),
	}
	go w.read(names)
	return w, nil
}

func (w *imageWatch) read(names map[string]struct{}) {
	defer close(w.exited)
	buf := make([]byte, 4096)
	for {
		n, err := w.f.Read(buf)
		if err != nil {
			return // closed
		}
		for off := 0; off+unix.SizeofInotifyEvent <= n; {
			mask := binary.NativeEndian.Uint32(buf[off+4:])
			end := off + unix.SizeofInotifyEvent + int(binary.NativeEndian.Uint32(buf[off+12:]))
			if end > n {
				break
			}
			name := string(bytes.TrimRight(buf[off+unix.SizeofInotifyEvent:end], "\x00"))
			off = end
			if _, ok := names[name]; ok || mask&unix.IN_Q_OVERFLOW != 0 {
				select {
				case w.changed <- struct{}{}:
				default:
				}
			}
		}
	}
}

// Close stops the watch and waits for its reader.
func (w *imageWatch) Close() {
	_ = w.f.Close() // an inotify descriptor holds no data to flush
	<-w.exited
}
