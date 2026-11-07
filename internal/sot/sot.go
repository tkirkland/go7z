// Package SoT locates and runs the pinned 7-Zip 26.05 SoT binary.
//
// The SoT is the sole behavioural reference for the module. It is used
// only after its SHA-256 matches the pinned value.
package sot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	// PinnedSHA256 of tools/sot/7zr.exe: release tag 26.05 of
	// github.com/ip7z/7zip, asset "7zr.exe".
	PinnedSHA256 = "9bf582b894dfa665f852d7e9112b02290a1c303c2d95a21fcdc41ffcb03143b7"
	// PinnedVersionLine printed by the verified binary.
	PinnedVersionLine = "7-Zip (r) 26.05 (x86) : Igor Pavlov : Public domain : 2026-10-21"
)

// Binary returns the verified path to tools/sot/7zr.exe, searching upward
// from dir for the repository root.
func Binary(dir string) (string, error) {
	for d := dir; ; d = filepath.Dir(d) {
		p := filepath.Join(d, "tools", "SoT", "7zr.exe")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return verify(p)
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", fmt.Errorf("tools/sot/7zr.exe not found above %s (run tools/fetch-sot.ps1)", dir)
		}
	}
}

func verify(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != PinnedSHA256 {
		return "", fmt.Errorf("SoT SHA-256 mismatch: %s is not the pinned 7zr 26.05 binary (run tools/fetch-sot.ps1)", path)
	}
	return path, nil
}

// Run executes the verified SoT with args, using dir as the working
// directory, and returns its combined stdout and stderr. The returned error
// covers both verification and the process exit status.
func Run(dir string, args ...string) ([]byte, error) {
	path, err := Binary(dir)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(path, args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err = cmd.Run()
	return buf.Bytes(), err
}

// RunBinary executes the already verified SoT at path with args, using
// dir as the working directory, and returns its combined output.
func RunBinary(path, dir string, args ...string) ([]byte, error) {
	cmd := exec.Command(path, args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}
