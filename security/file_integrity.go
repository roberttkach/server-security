package security

import (
	"crypto/sha256"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

type FileIntegrityMonitor struct {
	dirPath  string
	lastHash map[string][32]byte
}

var (
	integrityViolatedDirs []string
	integrityViolatedMux  sync.Mutex
)

func NewFileIntegrityMonitor(dirPath string) *FileIntegrityMonitor {
	return &FileIntegrityMonitor{
		dirPath:  dirPath,
		lastHash: make(map[string][32]byte),
	}
}

func (f *FileIntegrityMonitor) ComputeHash(filePath string) ([32]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error opening file: %v", err)
		return [32]byte{}, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("Error closing file: %v", err)
		}
	}(file)

	content, err := io.ReadAll(file)
	if err != nil {
		log.Printf("Error reading file: %v", err)
		return [32]byte{}, err
	}

	hash := sha256.Sum256(content)
	return hash, nil
}

func (f *FileIntegrityMonitor) fileIntegrityViolated() bool {
	err := filepath.Walk(f.dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Error accessing path: %v", err)
			return err
		}

		if !info.IsDir() {
			currentHash, err := f.ComputeHash(path)
			if err != nil {
				log.Printf("Error computing hash: %v", err)
				return err
			}

			if lastHash, ok := f.lastHash[path]; ok && lastHash != currentHash {
				f.lastHash[path] = currentHash
				integrityViolatedMux.Lock()
				integrityViolatedDirs = append(integrityViolatedDirs, path)
				integrityViolatedMux.Unlock()
				return nil
			}

			f.lastHash[path] = currentHash
		}
		return nil
	})

	if err != nil {
		log.Printf("Error walking the path %v: %v", f.dirPath, err)
		return true
	}
	return false
}

func GetIntegrityViolatedDirs() []string {
	integrityViolatedMux.Lock()
	defer integrityViolatedMux.Unlock()
	return integrityViolatedDirs
}

// MonitorFileIntegrity function for checking file integrity
func MonitorFileIntegrity(logger *log.Logger, dirPath string) {
	fileMonitor := NewFileIntegrityMonitor(dirPath)
	if fileMonitor.fileIntegrityViolated() {
		logger.Println("Unauthorized file changes detected")
	} else {
		logger.Println("No changes detected")
	}
}
