//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

// imageWatchMask: a file appears (create, rename into place, a finished write),
// goes away or changes its attributes in a directory that holds a trusted
// image, or the directory itself is moved or removed. A package upgrade replaces
// the binary by rename, and a restart may follow within milliseconds, so the 5 s
// refresh alone would miss the new file's identity at the first exec.
const imageWatchMask = unix.IN_CREATE | unix.IN_MOVED_TO | unix.IN_CLOSE_WRITE | unix.IN_ATTRIB |
	unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_ONLYDIR

// imageWatch reports on changed that a file which could be a trusted image
// changed on disk. The channel holds one signal: a burst of events is one
// refresh. The directories are those of PID 1's root, the view the images are
// read in, and one that does not exist yet, was moved or was removed, or that a
// symlink in its path leads away from, is watched again by rearm.
type imageWatch struct {
	f       *os.File
	inotify int // f's descriptor, kept so Fd() never switches f to blocking reads
	root    int // O_PATH descriptor of PID 1's root
	changed chan struct{}
	exited  chan struct{}
	dirs    []string // every directory of the trusted paths

	mu    sync.Mutex
	armed map[string]armedDir
}

// armedDir is the watch behind a directory name and the directory (device and
// inode) it was set on. A name that is a symlink, or whose directory was
// replaced, can lead to another directory later while the watch stays on the old
// one.
type armedDir struct {
	wd       int
	dev, ino uint64
}

// watchProtectedImages watches the directories of every path in imagePaths,
// inside the root of the process procRoot/1, and signals for the basenames of
// those paths only. A directory that does not exist is skipped until rearm finds
// it. It fails only when it cannot start watching at all, which includes PID 1's
// root being unreadable (the agent lacks CAP_SYS_PTRACE: no image could be
// identified either). Close the result when done.
func watchProtectedImages(s *ProtectedProcessSet, procRoot string) (*imageWatch, error) {
	root, err := unix.Open(filepath.Join(procRoot, "1", "root"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open the root of pid 1: %w", err)
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		_ = unix.Close(root) // an O_PATH descriptor holds no data to flush
		return nil, fmt.Errorf("inotify_init1: %w", err)
	}
	dirs := make(map[string]struct{})
	names := make(map[string]struct{})
	for p := range s.imagePaths() {
		dirs[filepath.Dir(p)] = struct{}{}
		names[filepath.Base(p)] = struct{}{}
	}
	w := &imageWatch{
		f:       os.NewFile(uintptr(fd), "inotify"),
		inotify: fd,
		root:    root,
		changed: make(chan struct{}, 1),
		exited:  make(chan struct{}),
		armed:   make(map[string]armedDir),
	}
	for d := range dirs {
		w.dirs = append(w.dirs, d)
	}
	w.rearm()
	go w.read(names)
	return w, nil
}

// rearm watches the directories that are not watched: one that did not exist
// when the watch started, that was moved or removed since, or whose name leads
// to another directory now (a symlink pointed at a new release). It returns how
// many it armed. Call it before each refresh: a file that appeared in a
// directory before it was armed is then seen by the refresh itself.
func (w *imageWatch) rearm() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, dir := range w.dirs {
		fd, err := openDirIn(w.root, dir, true)
		if err != nil {
			continue // not there (yet), or not a directory
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			_ = unix.Close(fd) // an O_PATH descriptor holds no data to flush
			continue
		}
		now := armedDir{dev: uint64(st.Dev), ino: uint64(st.Ino)}
		if old, ok := w.armed[dir]; ok {
			if old.dev == now.dev && old.ino == now.ino {
				_ = unix.Close(fd) // an O_PATH descriptor holds no data to flush
				continue
			}
			delete(w.armed, dir)
			w.removeUnlessShared(old.wd)
		}
		wd, err := unix.InotifyAddWatch(w.inotify, "/proc/self/fd/"+strconv.Itoa(fd), imageWatchMask)
		_ = unix.Close(fd) // an O_PATH descriptor holds no data to flush
		if err != nil {
			continue
		}
		now.wd = wd
		w.armed[dir] = now
		n++
	}
	return n
}

// removeUnlessShared drops the watch behind wd when no other directory name
// leads to the same directory. Callers hold mu.
func (w *imageWatch) removeUnlessShared(wd int) {
	for _, a := range w.armed {
		if a.wd == wd {
			return
		}
	}
	_, _ = unix.InotifyRmWatch(w.inotify, uint32(wd)) // the watch may be gone already
}

// armedDirs is the number of directories being watched.
func (w *imageWatch) armedDirs() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.armed)
}

// unarm forgets the directories behind a watch descriptor the kernel removed or
// that must be replaced, so the next rearm adds them again.
func (w *imageWatch) unarm(wd int, remove bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for dir, a := range w.armed {
		if a.wd == wd {
			delete(w.armed, dir)
		}
	}
	if remove {
		_, _ = unix.InotifyRmWatch(w.inotify, uint32(wd)) // the watch may be gone already
	}
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
			wd := int(int32(binary.NativeEndian.Uint32(buf[off:])))
			mask := binary.NativeEndian.Uint32(buf[off+4:])
			end := off + unix.SizeofInotifyEvent + int(binary.NativeEndian.Uint32(buf[off+12:]))
			if end > n {
				break
			}
			name := string(bytes.TrimRight(buf[off+unix.SizeofInotifyEvent:end], "\x00"))
			off = end
			// The directory itself went away or moved: a new one may take its
			// place with a new binary in it.
			self := mask&(unix.IN_IGNORED|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF) != 0
			if self {
				w.unarm(wd, mask&unix.IN_MOVE_SELF != 0)
			}
			if _, ok := names[name]; ok || self || mask&unix.IN_Q_OVERFLOW != 0 {
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
	_ = unix.Close(w.root) // an O_PATH descriptor holds no data to flush
}
