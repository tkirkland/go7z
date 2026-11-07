// Package sot locates and runs the pinned 7-Zip 26.05 SoT (source of
// truth) binaries, one per lane.
//
// 7-Zip ships a 32-bit and a 64-bit build of the same source, and the
// two write different bytes wherever the source branches on
// sizeof(size_t) or on available memory. Each lane's binary is the sole
// behavioural reference for that lane. A binary is used only after its
// SHA-256 and its version line match the pinned values.
package sot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Lane selects one of the two 7-Zip builds.
type Lane int

const (
	// Lane32 is the x86 build: tools/sot/7za-x86.exe (7za.exe in
	// 7z2605-extra.7z).
	Lane32 Lane = 32
	// Lane64 is the x64 build: tools/sot/7za-x64.exe (x64/7za.exe in
	// 7z2605-extra.7z).
	Lane64 Lane = 64
)

// Lanes lists both lanes in reporting order.
var Lanes = []Lane{Lane32, Lane64}

type laneInfo struct {
	file    string
	sha256  string
	version string
}

var lanes = map[Lane]laneInfo{
	Lane32: {
		file:    "7za-x86.exe",
		sha256:  "357929ec748d00728c64dd2e7aa0069258f40847c1410014bb60d22eb9ec75d5",
		version: "7-Zip (a) 26.05 (x86) : Copyright (c) 1999-2026 Igor Pavlov : 2026-10-21",
	},
	Lane64: {
		file:    "7za-x64.exe",
		sha256:  "7ddf0a3bc451e166679296be630d6f0573eb386159c04184761c43020c484291",
		version: "7-Zip (a) 26.05 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-10-21",
	},
}

// String returns "32" or "64".
func (l Lane) String() string { return fmt.Sprint(int(l)) }

// File is the binary's file name under tools/sot.
func (l Lane) File() string { return lanes[l].file }

// SHA256 is the pinned hash of the lane's binary.
func (l Lane) SHA256() string { return lanes[l].sha256 }

// VersionLine is the line the lane's binary prints first.
func (l Lane) VersionLine() string { return lanes[l].version }

// SizeT is sizeof(size_t) of the lane's build: 4 or 8. The public-domain
// encoder branches on it (default dictionary per level, largest accepted
// dictionary).
func (l Lane) SizeT() int { return int(l) / 8 }

// Binary returns the verified path to the lane's binary, searching upward
// from dir for the repository root (the directory holding tools/sot).
func Binary(dir string, lane Lane) (string, error) {
	info, ok := lanes[lane]
	if !ok {
		return "", fmt.Errorf("sot: unknown lane %d", int(lane))
	}
	for d := dir; ; d = filepath.Dir(d) {
		p := filepath.Join(d, "tools", "sot", info.file)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return verify(p, lane)
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", fmt.Errorf("tools/sot/%s not found above %s (run tools/fetch-sot.ps1)", info.file, dir)
		}
	}
}

// verified caches the outcome of verify per path, so that the hash and
// the version line are checked once per process and not once per case.
var verified sync.Map // path -> error (nil when verified)

func verify(path string, lane Lane) (string, error) {
	if v, ok := verified.Load(path); ok {
		if v == nil {
			return path, nil
		}
		return "", v.(error)
	}
	err := check(path, lane)
	if err == nil {
		verified.Store(path, nil)
		return path, nil
	}
	verified.Store(path, err)
	return "", err
}

func check(path string, lane Lane) error {
	info := lanes[lane]
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != info.sha256 {
		return fmt.Errorf("SoT SHA-256 mismatch: %s is not the pinned 7za 26.05 %s-bit binary (run tools/fetch-sot.ps1)", path, lane)
	}
	out, _ := RunBinary(path, filepath.Dir(path))
	got := ""
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimRight(line, "\r"); line != "" {
			got = line
			break
		}
	}
	if got != info.version {
		return fmt.Errorf("SoT version line mismatch for lane %s: got %q, want %q", lane, got, info.version)
	}
	return nil
}

// Run executes the lane's verified binary with args, using dir as the
// working directory, and returns its combined stdout and stderr. The
// returned error covers both verification and the process exit status.
func Run(dir string, lane Lane, args ...string) ([]byte, error) {
	path, err := Binary(dir, lane)
	if err != nil {
		return nil, err
	}
	return RunBinary(path, dir, args...)
}

// RunBinary executes the already verified binary at path with args, using
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
