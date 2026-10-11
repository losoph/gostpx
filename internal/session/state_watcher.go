package session

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// StateWatcher monitors state.json for updates across processes (e.g. CLI vs tray).
type StateWatcher struct {
	stop      chan struct{}
	closeOnce sync.Once

	mu         sync.Mutex
	closed     bool
	generation uint64
	timer      *time.Timer
	cbWg       sync.WaitGroup
}

// WatchState starts watching statePath's directory for Write, Create, or Rename events
// targeting statePath. It debounces notifications by 100ms, and reconnects with backoff
// if the filesystem watcher encounters an error or directory is temporarily missing.
func WatchState(statePath string, onChange func()) (*StateWatcher, error) {
	targetPath := filepath.Clean(statePath)
	dir := filepath.Dir(targetPath)
	base := filepath.Base(targetPath)

	w := &StateWatcher{
		stop: make(chan struct{}),
	}

	scheduleTrigger := func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.closed {
			return
		}
		w.generation++
		gen := w.generation

		if w.timer != nil {
			w.timer.Stop()
		}
		w.timer = time.AfterFunc(100*time.Millisecond, func() {
			w.mu.Lock()
			if w.closed || w.generation != gen {
				w.mu.Unlock()
				return
			}
			w.cbWg.Add(1)
			w.mu.Unlock()

			defer w.cbWg.Done()

			if onChange != nil {
				onChange()
			}
		})
	}

	go w.supervise(dir, base, targetPath, scheduleTrigger)

	return w, nil
}

func (w *StateWatcher) supervise(dir, base, targetPath string, trigger func()) {
	backoff := 100 * time.Millisecond
	for {
		select {
		case <-w.stop:
			return
		default:
		}

		if err := os.MkdirAll(dir, 0755); err != nil {
			select {
			case <-w.stop:
				return
			case <-time.After(backoff):
				if backoff < 2*time.Second {
					backoff *= 2
				}
				continue
			}
		}

		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			select {
			case <-w.stop:
				return
			case <-time.After(backoff):
				if backoff < 2*time.Second {
					backoff *= 2
				}
				continue
			}
		}

		if err := watcher.Add(dir); err != nil {
			_ = watcher.Close()
			select {
			case <-w.stop:
				return
			case <-time.After(backoff):
				if backoff < 2*time.Second {
					backoff *= 2
				}
				continue
			}
		}

		// Reset backoff on successful initialization
		backoff = 100 * time.Millisecond

		w.eventLoop(watcher, base, targetPath, trigger)
	}
}

func (w *StateWatcher) eventLoop(watcher *fsnotify.Watcher, base, targetPath string, trigger func()) {
	defer watcher.Close()
	for {
		select {
		case <-w.stop:
			return
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			evClean := filepath.Clean(ev.Name)
			if evClean == targetPath || filepath.Base(evClean) == base {
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
					trigger()
				}
			}
		case _, ok := <-watcher.Errors:
			if !ok {
				return
			}
			return
		}
	}
}

// Close stops the watcher, cancels any pending debounced triggers, and waits for any active callback to complete.
func (w *StateWatcher) Close() error {
	w.closeOnce.Do(func() {
		close(w.stop)

		w.mu.Lock()
		w.closed = true
		w.generation++
		if w.timer != nil {
			w.timer.Stop()
		}
		w.mu.Unlock()

		w.cbWg.Wait()
	})
	return nil
}
