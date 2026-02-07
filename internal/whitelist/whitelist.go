package whitelist

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

// Whitelist checks if a given finding should be considered neutral.
type Whitelist struct {
	mu    sync.RWMutex
	items map[string]bool
	path  string
}

// NewWhitelist creates or loads a whitelist from the given path.
func NewWhitelist(path string) (*Whitelist, error) {
	w := &Whitelist{
		items: make(map[string]bool),
		path:  path,
	}
	if err := w.load(); err != nil {
		// If file doesn't exist, we just start empty
		if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return w, nil
}

// load reads the whitelist file line by line.
func (w *Whitelist) load() error {
	file, err := os.Open(w.path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			w.items[line] = true
		}
	}
	return scanner.Err()
}

// Contains checks if the value is in the whitelist.
func (w *Whitelist) Contains(value string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.items[strings.TrimSpace(value)]
}

// Add adds a new value to the whitelist and persists it to disk.
func (w *Whitelist) Add(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.items[value] {
		return nil
	}
	w.items[value] = true

	// Append to file
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(value + "\n"); err != nil {
		return err
	}
	return nil
}
