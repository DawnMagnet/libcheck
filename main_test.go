//go:build linux

package main

import (
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitVer(t *testing.T) {
	for _, tc := range []struct{ in, fam, ver string }{
		{"GLIBC_2.34", "GLIBC", "2.34"},
		{"GLIBCXX_3.4.32", "GLIBCXX", "3.4.32"},
		{"CXXABI_1.3.13", "CXXABI", "1.3.13"},
		{"GLIBC_PRIVATE", "GLIBC_PRIVATE", ""},
		{"LIBSELINUX_1.0", "LIBSELINUX", "1.0"},
		{"libc.so.6", "libc.so.6", ""},
	} {
		if fam, ver := splitVer(tc.in); fam != tc.fam || ver != tc.ver {
			t.Errorf("splitVer(%q) = (%q, %q), want (%q, %q)", tc.in, fam, ver, tc.fam, tc.ver)
		}
	}
}

func TestCmpVer(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"2.36", "2.4", 1},
		{"2.4", "2.36", -1},
		{"2.34", "2.34", 0},
		{"3.4.32", "3.4.9", 1},
		{"2.2.5", "2.2", 1},
		{"2.2", "2.2.0", 0},
	} {
		if got := cmpVer(tc.a, tc.b); got != tc.want {
			t.Errorf("cmpVer(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
	if got := maxVer([]string{"2.4", "2.36", "2.17", ""}); got != "2.36" {
		t.Errorf("maxVer = %q, want 2.36", got)
	}
}

// dynamicSample returns the path of a dynamically linked executable on this host.
func dynamicSample(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"sh", "ls", "cat"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		f, err := elf.Open(p)
		if err != nil {
			continue
		}
		libs, _ := f.ImportedLibraries()
		f.Close()
		if len(libs) > 0 {
			return p
		}
	}
	t.Skip("no dynamically linked sample binary found")
	return ""
}

// patchedCopy copies src into a temp dir, replacing every NUL-terminated
// occurrence of from with to (same length), and returns the new path.
func patchedCopy(t *testing.T, src, from, to string) string {
	t.Helper()
	if len(from) != len(to) {
		t.Fatalf("patch strings differ in length: %q vs %q", from, to)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	old, repl := []byte(from+"\x00"), []byte(to+"\x00")
	if !bytes.Contains(b, old) {
		t.Fatalf("%q not found in %s", from, src)
	}
	dst := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(dst, bytes.ReplaceAll(b, old, repl), 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
}

func run(t *testing.T, path string, verbose bool) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	rc := check(&buf, path, verbose, nil)
	return rc, buf.String()
}

func TestHostBinaryCanRun(t *testing.T) {
	rc, out := run(t, dynamicSample(t), false)
	if rc != 0 || !strings.Contains(out, "RESULT: CAN RUN") {
		t.Fatalf("rc=%d, want a pass:\n%s", rc, out)
	}
}

func TestVerboseListsLibraries(t *testing.T) {
	_, out := run(t, dynamicSample(t), true)
	if !strings.Contains(out, "<-") {
		t.Fatalf("verbose output lists no loaded libraries:\n%s", out)
	}
}

func TestMissingLibrary(t *testing.T) {
	sample := dynamicSample(t)
	f, err := elf.Open(sample)
	if err != nil {
		t.Fatal(err)
	}
	libs, _ := f.ImportedLibraries()
	f.Close()
	name := libs[0]
	rc, out := run(t, patchedCopy(t, sample, name, name[:len(name)-1]+"Z"), false)
	if rc != 1 || !strings.Contains(out, "RESULT: CANNOT RUN") || !strings.Contains(out, "missing libraries") {
		t.Fatalf("rc=%d, want a missing-library failure:\n%s", rc, out)
	}
}

func TestSymbolVersionTooNew(t *testing.T) {
	sample := dynamicSample(t)
	f, err := elf.Open(sample)
	if err != nil {
		t.Fatal(err)
	}
	needs, _ := f.DynamicVersionNeeds()
	f.Close()
	var dep string
	for _, n := range needs {
		for _, d := range n.Needs {
			if strings.HasPrefix(d.Dep, "GLIBC_2.") {
				dep = d.Dep
			}
		}
	}
	if dep == "" {
		t.Skip("sample has no GLIBC version requirements (non-glibc host)")
	}
	rc, out := run(t, patchedCopy(t, sample, dep, "GLIBC_9"+strings.TrimPrefix(dep, "GLIBC_2")), false)
	if rc != 1 || !strings.Contains(out, "RESULT: CANNOT RUN") || !strings.Contains(out, "missing GLIBC_9") {
		t.Fatalf("rc=%d, want a version failure:\n%s", rc, out)
	}
}

func TestNotELF(t *testing.T) {
	p := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(p, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc, _ := run(t, p, false); rc != 2 {
		t.Fatalf("rc=%d, want 2 for a non-ELF file", rc)
	}
}

func TestMissingFile(t *testing.T) {
	if rc, _ := run(t, filepath.Join(t.TempDir(), "nope"), false); rc != 2 {
		t.Fatalf("rc=%d, want 2 for a missing file", rc)
	}
}
