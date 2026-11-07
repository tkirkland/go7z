package sottest

import (
	"encoding/binary"
	"fmt"

	"github.com/tkirkland/go7z/sevenzip"
)

// Synthetic executable images for the filter automation cases. The
// SoT's analysis looks only at the headers (analyze.go), so patched
// machine fields over real PE data and minimal ELF/Mach-O headers over
// deterministic data exercise every branch.

// PatchPEMachine returns a copy of a PE image with its machine field
// set.
func PatchPEMachine(pe []byte, machine uint16) []byte {
	out := append([]byte(nil), pe...)
	off := binary.LittleEndian.Uint32(out[0x3C:])
	binary.LittleEndian.PutUint16(out[off+4:], machine)
	return out
}

// SynthELF returns a minimal ELF header (class 1 or 2, data 1 or 2,
// version 1, type 2, the machine) followed by n bytes of data.
func SynthELF(class, data byte, machine uint16, n int) []byte {
	h := make([]byte, 20)
	copy(h, "\x7fELF")
	h[4], h[5], h[6] = class, data, 1
	if data == 2 {
		binary.BigEndian.PutUint16(h[16:], 2)
		binary.BigEndian.PutUint16(h[18:], machine)
	} else {
		binary.LittleEndian.PutUint16(h[16:], 2)
		binary.LittleEndian.PutUint16(h[18:], machine)
	}
	return append(h, DeterministicData(n)...)
}

// SynthMachO returns a minimal Mach-O header (little-endian magic,
// cputype) followed by n bytes of data.
func SynthMachO(magic, cputype uint32, n int) []byte {
	h := make([]byte, 32)
	binary.LittleEndian.PutUint32(h, magic)
	binary.LittleEndian.PutUint32(h[4:], cputype)
	binary.LittleEndian.PutUint32(h[12:], 2)
	binary.LittleEndian.PutUint32(h[16:], 1)
	binary.LittleEndian.PutUint32(h[20:], 256)
	return append(h, DeterministicData(n)...)
}

// AutoCases returns the filter-automation cases (-mf=on by default):
// real and patched PE images, ELF and Mach-O headers, the extension
// sets per -myx level, the size thresholds, the level at which x86
// switches to BCJ2, the lc/lp the ARM filters imply for LZMA, PPMd and
// Copy behind the automatic filters, -mf=off, -myx0 and -mx0, solid
// grouping and -ms=off, and encryption. exe is the lane's SoT binary.
func AutoCases(exe []byte) []SevenZCase {
	var cases []SevenZCase
	add := func(name string, files []TreeFile, inputs []string, args []string, opts sevenzip.Options) {
		cases = append(cases, SevenZCase{Name: "auto_" + name, Files: files, Inputs: inputs, Args: args, Opts: opts})
	}
	pe := exe[:300000]
	lfanew := int(binary.LittleEndian.Uint32(pe[0x3C:]))
	arm64 := PatchPEMachine(pe, 0xAA64)
	arm := PatchPEMachine(pe, 0x01C0)
	armt2 := PatchPEMachine(pe, 0x01C2)
	armt := PatchPEMachine(pe, 0x01C4)
	i386 := PatchPEMachine(pe, 0x014C)
	ppc := PatchPEMachine(pe, 0x01F0)
	riscv := PatchPEMachine(pe, 0x5064)
	elfX64 := SynthELF(2, 1, 0x3E, 200000)
	elfX86 := SynthELF(1, 1, 3, 200000)
	elfARM := SynthELF(1, 1, 0x28, 200000)
	elfARM64 := SynthELF(2, 1, 0xB7, 200000)
	elfRISCV := SynthELF(2, 1, 0xF3, 200000)
	elfBE := SynthELF(2, 2, 0x28, 200000)
	elfV2 := SynthELF(2, 1, 0x3E, 200000)
	elfV2[6] = 2
	machoX64 := SynthMachO(0xFEEDFACF, 0x01000007, 200000)
	machoX86 := SynthMachO(0xFEEDFACE, 7, 200000)
	machoARM := SynthMachO(0xFEEDFACE, 0xC, 200000)
	machoARM64 := SynthMachO(0xFEEDFACF, 0x0100000C, 200000)
	machoBE := SynthMachO(0xCFFAEDFE, 0x0C000001, 200000)
	fat := SynthMachO(0xBEBAFECA, 2, 200000)
	rnd := DeterministicData(200000)

	all := []TreeFile{
		{"t/p1.txt", rnd}, {"t/p2.bin", TextLike(100001)},
		{"t/x1.exe", pe}, {"t/x2.dll", i386}, {"t/x3.so", elfX64}, {"t/x4.sys", elfX86}, {"t/x5.dylib", machoX64}, {"t/x6.ocx", machoX86},
		{"t/q1.exe", arm64}, {"t/q2.so", elfARM64}, {"t/q3.dylib", machoARM64},
		{"t/r1.exe", arm}, {"t/r2.exe", armt2}, {"t/r3.so", elfARM}, {"t/r4.dylib", machoARM}, {"t/r5.so", elfBE},
		{"t/s1.exe", armt},
		{"t/n1.exe", ppc}, {"t/n2.exe", riscv}, {"t/n3.so", elfRISCV}, {"t/n4.so", elfV2}, {"t/n5.dylib", machoBE}, {"t/n6.dylib", fat},
		{"t/n7.exe", rnd}, {"t/n8.bin", pe}, {"t/n9.o", elfX64}, {"t/n10.elf", elfX64}, {"t/noext", elfX64},
		{"t/v1.so.1", elfX64}, {"t/v2.so.1.2.3", elfX64}, {"t/v3.so.abc", elfX64}, {"t/v4.dll.1", elfX64}, {"t/v5.EXE", pe}, {"t/v6.So", elfARM},
		{"t/sub/d1.dll", pe}, {"t/sub/d2.txt", rnd}, {"t/empty.exe", nil}, {"t/dir/", nil},
	}
	add("tree", all, []string{"t"}, nil, sevenzip.Options{})
	add("tree_mf_on", all, []string{"t"}, []string{"-mf=on"}, sevenzip.Options{})
	add("tree_mf_off", all, []string{"t"}, []string{"-mf=off"}, sevenzip.Options{NoAutoFilter: true})
	for _, mx := range []int{1, 3, 7, 8, 9} {
		add(fmt.Sprintf("tree_mx%d", mx), all, []string{"t"}, []string{fmt.Sprintf("-mx=%d", mx)}, sevenzip.Options{Level: mx})
	}
	add("tree_mx0", all, []string{"t"}, []string{"-mx=0"}, sevenzip.Options{Level: sevenzip.LevelStore})
	for _, yx := range []int{0, 1, 4, 5, 6, 7, 8, 9} {
		o := sevenzip.Options{Analysis: yx}
		if yx == 0 {
			o.Analysis = sevenzip.AnalysisNone
		}
		add(fmt.Sprintf("tree_myx%d", yx), all, []string{"t"}, []string{fmt.Sprintf("-myx=%d", yx)}, o)
	}
	add("tree_myx9_mx9", all, []string{"t"}, []string{"-myx=9", "-mx=9"}, sevenzip.Options{Analysis: 9, Level: 9})
	add("tree_lzma", all, []string{"t"}, []string{"-m0=LZMA"}, sevenzip.Options{Method: sevenzip.LZMA})
	add("tree_lzma_mx9", all, []string{"t"}, []string{"-m0=LZMA", "-mx=9"}, sevenzip.Options{Method: sevenzip.LZMA, Level: 9})
	add("tree_ppmd", all, []string{"t"}, []string{"-m0=PPMd"}, sevenzip.Options{Method: sevenzip.PPMd})
	add("tree_copy", all, []string{"t"}, []string{"-m0=Copy"}, sevenzip.Options{Method: sevenzip.Copy})
	add("tree_ms_off", all, []string{"t"}, []string{"-ms=off"}, sevenzip.Options{SolidOff: true})
	add("tree_ms_300k", all, []string{"t"}, []string{"-ms=300k"}, sevenzip.Options{SolidSize: 300 << 10})
	add("tree_hc_off", all, []string{"t"}, []string{"-mhc=off"}, sevenzip.Options{NoHeaderCompression: true})
	add("tree_pw", all, []string{"t"}, []string{"-pTest"}, sevenzip.Options{Password: "Test"})
	add("tree_pw_mhe_mx9", all, []string{"t"}, []string{"-pTest", "-mhe", "-mx=9"}, sevenzip.Options{Password: "Test", EncryptHeader: true, Level: 9})

	// Size thresholds: PE needs 512 bytes from e_lfanew, ELF and Mach-O
	// 512 bytes in all.
	thr := []TreeFile{
		{"s/pe_lo.exe", pe[:lfanew+511]}, {"s/pe_hi.exe", pe[:lfanew+512]},
		{"s/pe_511.exe", pe[:511]}, {"s/pe_512.exe", pe[:512]},
		{"s/elf_511.so", elfX64[:511]}, {"s/elf_512.so", elfX64[:512]},
		{"s/macho_511.dylib", machoARM64[:511]}, {"s/macho_512.dylib", machoARM64[:512]},
		{"s/arm64_lo.exe", arm64[:lfanew+511]}, {"s/arm64_hi.exe", arm64[:lfanew+512]},
	}
	add("thresholds", thr, []string{"s"}, nil, sevenzip.Options{})
	add("thresholds_ms_off", thr, []string{"s"}, []string{"-ms=off"}, sevenzip.Options{SolidOff: true})

	one := func(name string, data []byte) {
		files := []TreeFile{{"in/" + name, data}}
		add("one_"+name, files, []string{"in/" + name}, nil, sevenzip.Options{})
		add("one_"+name+"_mx9", files, []string{"in/" + name}, []string{"-mx=9"}, sevenzip.Options{Level: 9})
		add("one_"+name+"_lzma", files, []string{"in/" + name}, []string{"-m0=LZMA"}, sevenzip.Options{Method: sevenzip.LZMA})
	}
	one("x64.exe", exe)
	one("arm64.exe", arm64)
	one("arm.exe", arm)
	one("armt.exe", armt)
	one("elfarm.so", elfARM)
	one("macho.dylib", machoX64)
	return cases
}
