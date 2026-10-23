package main

import (
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
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

func TestCombineExit(t *testing.T) {
	for _, tc := range []struct {
		in   []int
		want int
	}{
		{[]int{0, 0}, 0},
		{[]int{0, 3}, 3},
		{[]int{3, 1}, 1},
		{[]int{1, 2, 3}, 2},
		{nil, 0},
	} {
		if got := combineExit(tc.in...); got != tc.want {
			t.Errorf("combineExit(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func cli(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func requireLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("needs a Linux host")
	}
}

// dynamicSample returns the path of a dynamically linked executable on this host.
func dynamicSample(t *testing.T) string {
	t.Helper()
	requireLinux(t)
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

// glibcDep returns one GLIBC_2.x requirement of sample, or skips the test
// when the sample has none (for example on musl systems).
func glibcDep(t *testing.T, sample string) string {
	t.Helper()
	f, err := elf.Open(sample)
	if err != nil {
		t.Fatal(err)
	}
	needs, _ := f.DynamicVersionNeeds()
	f.Close()
	dep := ""
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
	return dep
}

// tooNewCopy returns a copy of sample that needs a GLIBC version nothing provides.
func tooNewCopy(t *testing.T, sample string) string {
	t.Helper()
	dep := glibcDep(t, sample)
	return patchedCopy(t, sample, dep, "GLIBC_9"+strings.TrimPrefix(dep, "GLIBC_2"))
}

func TestHostBinaryCanRun(t *testing.T) {
	code, out, _ := cli(t, dynamicSample(t))
	if code != 0 || !strings.Contains(out, "RESULT: CAN RUN") {
		t.Fatalf("code=%d, want a pass:\n%s", code, out)
	}
}

func TestVerboseListsLibraries(t *testing.T) {
	_, out, _ := cli(t, "-v", dynamicSample(t))
	if !strings.Contains(out, "<-") {
		t.Fatalf("verbose output lists no loaded libraries:\n%s", out)
	}
}

func TestFlagsAfterFile(t *testing.T) {
	sample := dynamicSample(t)
	_, out, _ := cli(t, sample, "-v")
	if !strings.Contains(out, "<-") {
		t.Fatalf("a flag after the file name was ignored:\n%s", out)
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
	code, out, _ := cli(t, patchedCopy(t, sample, name, name[:len(name)-1]+"Z"))
	if code != 1 || !strings.Contains(out, "RESULT: CANNOT RUN") || !strings.Contains(out, "missing libraries") {
		t.Fatalf("code=%d, want a missing-library failure:\n%s", code, out)
	}
}

func TestSymbolVersionTooNew(t *testing.T) {
	code, out, _ := cli(t, tooNewCopy(t, dynamicSample(t)))
	if code != 1 || !strings.Contains(out, "RESULT: CANNOT RUN") || !strings.Contains(out, "missing GLIBC_9") {
		t.Fatalf("code=%d, want a version failure:\n%s", code, out)
	}
}

func TestNotELF(t *testing.T) {
	p := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(p, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := cli(t, "-t", "all", p); code != 2 || !strings.Contains(errOut, "not a valid ELF") {
		t.Fatalf("code=%d stderr=%q, want 2 for a non-ELF file", code, errOut)
	}
}

func TestMissingFile(t *testing.T) {
	if code, _, _ := cli(t, filepath.Join(t.TempDir(), "nope")); code != 2 {
		t.Fatalf("code=%d, want 2 for a missing file", code)
	}
}

func TestRootFSResolvesSymlinksInsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs elevated rights on Windows")
	}
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755))
	must(os.WriteFile(filepath.Join(root, "usr/lib/libx.so.1"), []byte("x"), 0o644))
	must(os.Symlink("usr/lib", filepath.Join(root, "lib")))    // relative
	must(os.Symlink("/usr/lib", filepath.Join(root, "lib64"))) // absolute: must stay inside root
	must(os.Symlink("/lib/../lib/libx.so.1", filepath.Join(root, "usr/lib/libx.so")))
	must(os.Symlink("loop", filepath.Join(root, "loop")))

	r := rootFS{root}
	want := filepath.Join(root, "usr/lib/libx.so.1")
	for _, p := range []string{"/lib/libx.so.1", "/lib64/libx.so.1", "/usr/lib/libx.so", "/usr/../lib/libx.so.1"} {
		if got, err := r.real(p); err != nil || got != want {
			t.Errorf("real(%q) = %q, %v; want %q", p, got, err, want)
		}
	}
	if _, err := r.real("/loop"); err == nil {
		t.Error("real(/loop) succeeded, want a symlink loop error")
	}
	if got := r.glob("/lib/libx.so*"); len(got) != 2 {
		t.Errorf("glob = %v, want 2 matches", got)
	}
}

func hostProfile(t *testing.T) *Profile {
	t.Helper()
	requireLinux(t)
	p, err := snapshot(snapshotOpts{Root: "/", Complete: true})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func saveProfile(t *testing.T, p *Profile) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), p.ID+"."+p.Arch+".json.gz")
	var buf bytes.Buffer
	if err := writeProfile(&buf, p, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestSnapshotRoundTrip(t *testing.T) {
	sample := dynamicSample(t)
	prof := saveProfile(t, hostProfile(t))

	code, out, _ := cli(t, "-t", prof, sample)
	if code != 0 || !strings.Contains(out, "target: ") || !strings.Contains(out, "RESULT: CAN RUN") {
		t.Fatalf("code=%d, want a pass against the host's own snapshot:\n%s", code, out)
	}
	code, out, _ = cli(t, "-t", prof, tooNewCopy(t, sample))
	if code != 1 || !strings.Contains(out, "the target provides only up to") {
		t.Fatalf("code=%d, want a version failure against the snapshot:\n%s", code, out)
	}
}

func TestBaseImageTargetNeedsPackages(t *testing.T) {
	sample := dynamicSample(t)
	f, err := elf.Open(sample)
	if err != nil {
		t.Fatal(err)
	}
	libs, _ := f.ImportedLibraries()
	f.Close()

	p := hostProfile(t)
	p.ID, p.Complete = "base-image", false
	gone := libs[0]
	for path, idx := range p.Paths {
		if p.Objects[idx].Soname == gone || filepath.Base(path) == gone {
			delete(p.Paths, path)
		}
	}
	code, out, _ := cli(t, "-t", saveProfile(t, p), sample)
	if code != 3 || !strings.Contains(out, "AFTER INSTALLING") || !strings.Contains(out, gone) {
		t.Fatalf("code=%d, want 3 and an install hint for %s:\n%s", code, gone, out)
	}

	p.Complete = true
	if code, _, _ := cli(t, "-t", saveProfile(t, p), sample); code != 1 {
		t.Fatalf("code=%d, want 1 when a complete system lacks %s", code, gone)
	}
}

func TestMatrixForSeveralTargets(t *testing.T) {
	sample := dynamicSample(t)
	glibcDep(t, sample)
	good := hostProfile(t)
	good.ID = "newer-distro"

	old := hostProfile(t)
	old.ID = "older-distro"
	for i, o := range old.Objects {
		if o.Soname != "libc.so.6" {
			continue
		}
		var keep []string
		for _, d := range o.Defs {
			if _, v := splitVer(d); v == "" || cmpVer(v, "2.2.5") <= 0 {
				keep = append(keep, d)
			}
		}
		old.Objects[i].Defs = keep
	}

	code, out, _ := cli(t, "-t", saveProfile(t, good), "-t", saveProfile(t, old), sample)
	for _, want := range []string{"TARGET", "newer-distro", "older-distro", "CAN RUN", "CANNOT RUN", "1 of 2 targets can run it"} {
		if !strings.Contains(out, want) {
			t.Errorf("matrix lacks %q:\n%s", want, out)
		}
	}
	if code != 1 {
		t.Errorf("code=%d, want 1 when any target fails", code)
	}
}

func profileFS(t *testing.T, ps ...*Profile) fstest.MapFS {
	t.Helper()
	fsys := fstest.MapFS{}
	for _, p := range ps {
		var buf bytes.Buffer
		if err := writeProfile(&buf, p, true); err != nil {
			t.Fatal(err)
		}
		fsys[embeddedDir+"/"+p.ID+"."+p.Arch+".json.gz"] = &fstest.MapFile{Data: buf.Bytes()}
	}
	return fsys
}

func TestResolveTargets(t *testing.T) {
	mk := func(id, arch string) *Profile {
		return &Profile{Schema: profileSchema, ID: id, Name: id, Arch: arch, Paths: map[string]int{}}
	}
	fsys := profileFS(t, mk("debian-12", "amd64"), mk("debian-12", "arm64"), mk("ubuntu-22.04", "amd64"), mk("rhel-9", "arm64"))

	ids := func(specs ...string) string {
		ps, err := resolveTargets(fsys, embeddedDir, specs, "amd64")
		if err != nil {
			return "error: " + err.Error()
		}
		var out []string
		for _, p := range ps {
			out = append(out, p.ID)
		}
		return strings.Join(out, ",")
	}
	for _, tc := range []struct {
		specs []string
		want  string
	}{
		{[]string{"debian-12"}, "debian-12"},
		{[]string{"ubuntu-22.04", "debian-12"}, "ubuntu-22.04,debian-12"},
		{[]string{"all"}, "debian-12,ubuntu-22.04"},
		{[]string{"debian-*", "all"}, "debian-12,ubuntu-22.04"},
		{[]string{"ubuntu-*"}, "ubuntu-22.04"},
		{[]string{"nope"}, `error: unknown target "nope" (run "libcheck targets" to list them)`},
		{[]string{"rhel-9"}, `error: target "rhel-9" has no amd64 profile (available: arm64)`},
		{[]string{"rhel-*"}, `error: no amd64 profile matches "rhel-*"`},
	} {
		if got := ids(tc.specs...); got != tc.want {
			t.Errorf("resolveTargets(%v) = %q, want %q", tc.specs, got, tc.want)
		}
	}
}

func TestProfileValidation(t *testing.T) {
	for name, data := range map[string]string{
		"wrong schema": `{"schema":99,"id":"x","arch":"amd64"}`,
		"no id":        `{"schema":1,"arch":"amd64"}`,
		"bad index":    `{"schema":1,"id":"x","arch":"amd64","paths":{"/lib/a.so":3}}`,
		"not json":     `hello`,
	} {
		if _, err := readProfile(strings.NewReader(data)); err == nil {
			t.Errorf("%s: readProfile succeeded, want an error", name)
		}
	}
}

func TestVersionFlag(t *testing.T) {
	if code, out, _ := cli(t, "-version"); code != 0 || !strings.HasPrefix(out, "libcheck ") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}
