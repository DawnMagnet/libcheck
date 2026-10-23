//go:build linux

// libcheck reports whether an ELF program can run on this host.
//
// It resolves every DT_NEEDED library the way ld.so does (RPATH,
// LD_LIBRARY_PATH, RUNPATH, ld.so.cache, default dirs) and checks each required
// symbol version (GLIBC_x.y, GLIBCXX_x.y, CXXABI_x.y, ...) against the versions
// the host libraries define. Static analysis only: dlopen()ed libraries and
// data files are not checked.
//
// Exit status: 0 = can run, 1 = cannot run, 2 = usage or input error.
package main

import (
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
)

var (
	verRe   = regexp.MustCompile(`^(.*?)_(\d+(?:\.\d+)*)$`)
	cacheRe = regexp.MustCompile(`(?m)^\s*(\S+) \(.*\) => (\S+)$`)
	kernRe  = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?`)

	hostMachine = map[string]elf.Machine{
		"amd64": elf.EM_X86_64, "386": elf.EM_386, "arm64": elf.EM_AARCH64,
		"arm": elf.EM_ARM, "ppc64le": elf.EM_PPC64, "ppc64": elf.EM_PPC64,
		"s390x": elf.EM_S390, "riscv64": elf.EM_RISCV,
	}
	platformName = map[string]string{
		"amd64": "x86_64", "386": "i686", "arm64": "aarch64", "arm": "armv7l",
	}
	useColor bool
)

func splitVer(name string) (fam, ver string) {
	if m := verRe.FindStringSubmatch(name); m != nil {
		return m[1], m[2]
	}
	return name, ""
}

func cmpVer(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func maxVer(vs []string) string {
	best := ""
	for _, v := range vs {
		if v != "" && (best == "" || cmpVer(v, best) > 0) {
			best = v
		}
	}
	return best
}

type object struct {
	path    string
	f       *elf.File
	needed  []string
	soname  string
	rpath   string
	runpath string
	interp  string
	needs   []elf.DynamicVersionNeed
	defs    map[string]bool
}

func openObject(path string) (*object, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	o := &object{path: path, f: f, defs: map[string]bool{}}
	fail := func(err error) (*object, error) {
		f.Close()
		return nil, err
	}
	if o.needed, err = f.DynString(elf.DT_NEEDED); err != nil {
		return fail(err)
	}
	first := func(tag elf.DynTag) string {
		if v, _ := f.DynString(tag); len(v) > 0 {
			return v[0]
		}
		return ""
	}
	o.soname, o.rpath, o.runpath = first(elf.DT_SONAME), first(elf.DT_RPATH), first(elf.DT_RUNPATH)
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			b := make([]byte, p.Filesz)
			if _, err := p.ReadAt(b, 0); err != nil {
				return fail(err)
			}
			o.interp = strings.TrimRight(string(b), "\x00")
		}
	}
	if f.SectionByType(elf.SHT_GNU_VERNEED) != nil {
		if o.needs, err = f.DynamicVersionNeeds(); err != nil {
			return fail(err)
		}
	}
	if f.SectionByType(elf.SHT_GNU_VERDEF) != nil {
		vs, err := f.DynamicVersions()
		if err != nil {
			return fail(err)
		}
		for _, v := range vs {
			if v.Flags&elf.VER_FLG_BASE == 0 {
				o.defs[v.Name] = true
			}
		}
	}
	return o, nil
}

func (o *object) runnable() bool { return o.f.Type == elf.ET_EXEC || o.interp != "" }

func (o *object) kind() string {
	switch {
	case o.f.SectionByType(elf.SHT_DYNAMIC) == nil && o.interp == "":
		return "static executable"
	case o.f.Type == elf.ET_EXEC:
		return "executable"
	case o.interp != "":
		return "PIE executable"
	}
	return "shared object"
}

// abiTag returns the minimum kernel version from .note.ABI-tag.
func (o *object) abiTag() ([3]uint32, bool) {
	var v [3]uint32
	s := o.f.Section(".note.ABI-tag")
	if s == nil {
		return v, false
	}
	d, err := s.Data()
	if err != nil || len(d) < 12 {
		return v, false
	}
	bo := o.f.ByteOrder
	namesz, descsz, typ := int(bo.Uint32(d[0:])), int(bo.Uint32(d[4:])), bo.Uint32(d[8:])
	off := 12 + ((namesz + 3) &^ 3)
	if typ != 1 || descsz < 16 || off+16 > len(d) || bo.Uint32(d[off:]) != 0 {
		return v, false
	}
	for i := range v {
		v[i] = bo.Uint32(d[off+4+4*i:])
	}
	return v, true
}

func realpath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		if a, err := filepath.Abs(r); err == nil {
			return a
		}
		return r
	}
	return p
}

type missingRef struct {
	by   *object
	name string
}

type loader struct {
	main     *object
	mainKey  string
	cache    map[string][]string
	defaults []string
	envDirs  []string
	objs     map[string]*object
	order    []string
	edges    map[string]map[string]string // object key -> needed name -> provider key ("" = missing)
	missing  []missingRef
}

func ldCache() map[string][]string {
	cache := map[string][]string{}
	for _, exe := range []string{"ldconfig", "/sbin/ldconfig", "/usr/sbin/ldconfig"} {
		cmd := exec.Command(exe, "-p")
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		for _, m := range cacheRe.FindAllStringSubmatch(string(out), -1) {
			cache[m[1]] = append(cache[m[1]], m[2])
		}
		if len(cache) > 0 {
			break
		}
	}
	return cache
}

func defaultDirs(haveCache bool) []string {
	dirs := []string{"/lib64", "/usr/lib64", "/lib", "/usr/lib"}
	if !haveCache {
		var conf func(pattern string)
		conf = func(pattern string) {
			files, _ := filepath.Glob(pattern)
			sort.Strings(files)
			for _, p := range files {
				b, err := os.ReadFile(p)
				if err != nil {
					continue
				}
				for _, line := range strings.Split(string(b), "\n") {
					line, _, _ = strings.Cut(line, "#")
					fields := strings.Fields(line)
					switch {
					case len(fields) == 0:
					case fields[0] == "include":
						for _, pat := range fields[1:] {
							if !filepath.IsAbs(pat) {
								pat = filepath.Join(filepath.Dir(p), pat)
							}
							conf(pat)
						}
					default:
						dirs = append(dirs, line)
					}
				}
			}
		}
		conf("/etc/ld.so.conf")
		a, _ := filepath.Glob("/lib/*-linux-gnu*")
		b, _ := filepath.Glob("/usr/lib/*-linux-gnu*")
		dirs = append(dirs, append(a, b...)...)
	}
	seen := map[string]bool{}
	var res []string
	for _, d := range dirs {
		d = strings.TrimSpace(d)
		if st, err := os.Stat(d); err == nil && st.IsDir() && !seen[d] {
			seen[d] = true
			res = append(res, d)
		}
	}
	return res
}

func newLoader(main *object, extra []string) *loader {
	cache := ldCache()
	l := &loader{
		main: main, mainKey: realpath(main.path), cache: cache,
		defaults: defaultDirs(len(cache) > 0),
		objs:     map[string]*object{}, edges: map[string]map[string]string{},
	}
	for _, p := range append(append([]string{}, extra...), strings.Split(os.Getenv("LD_LIBRARY_PATH"), ":")...) {
		if p != "" {
			l.envDirs = append(l.envDirs, p)
		}
	}
	l.objs[l.mainKey] = main
	l.order = append(l.order, l.mainKey)
	return l
}

func (l *loader) expand(o *object, spec string) []string {
	origin := filepath.Dir(realpath(o.path))
	lib := "lib"
	if o.f.Class == elf.ELFCLASS64 {
		lib = "lib64"
	}
	plat, ok := platformName[runtime.GOARCH]
	if !ok {
		plat = runtime.GOARCH
	}
	r := strings.NewReplacer("${ORIGIN}", origin, "$ORIGIN", origin, "${LIB}", lib, "$LIB", lib,
		"${PLATFORM}", plat, "$PLATFORM", plat)
	var res []string
	for _, p := range strings.Split(spec, ":") {
		if p = r.Replace(p); p != "" {
			res = append(res, p)
		}
	}
	return res
}

// openMatch opens path if it is an ELF with the same class and machine as the main object.
func (l *loader) openMatch(path string) *object {
	if o, ok := l.objs[realpath(path)]; ok {
		return o
	}
	o, err := openObject(path)
	if err != nil {
		return nil
	}
	if o.f.Class != l.main.f.Class || o.f.Machine != l.main.f.Machine {
		o.f.Close()
		return nil
	}
	return o
}

func (l *loader) find(name string, o *object, chain []string) *object {
	var cands []string
	if strings.Contains(name, "/") {
		cands = []string{name}
	} else {
		dirs := append(append([]string{}, chain...), l.envDirs...)
		if o.runpath != "" {
			dirs = append(dirs, l.expand(o, o.runpath)...)
		}
		for _, d := range dirs {
			cands = append(cands, filepath.Join(d, name))
		}
		cands = append(cands, l.cache[name]...)
		for _, d := range l.defaults {
			cands = append(cands, filepath.Join(d, name))
		}
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() {
			if m := l.openMatch(c); m != nil {
				return m
			}
		}
	}
	return nil
}

func (l *loader) load(o *object, parentChain []string) {
	key := realpath(o.path)
	chain := parentChain
	if o.rpath != "" && o.runpath == "" {
		chain = append(l.expand(o, o.rpath), parentChain...)
	}
	l.edges[key] = map[string]string{}
	for _, name := range o.needed {
		dep := l.find(name, o, chain)
		if dep == nil {
			l.edges[key][name] = ""
			l.missing = append(l.missing, missingRef{o, name})
			continue
		}
		dk := realpath(dep.path)
		l.edges[key][name] = dk
		if _, ok := l.objs[dk]; !ok {
			l.objs[dk] = dep
			l.order = append(l.order, dk)
			l.load(dep, chain)
		}
	}
}

func (l *loader) close() {
	for _, o := range l.objs {
		o.f.Close()
	}
}

type row struct {
	obj, lib, prov, fam, need, have string
	missing, weak                   []string
}

func (l *loader) versionRows() []row {
	var rows []row
	for _, key := range l.order {
		o := l.objs[key]
		type group struct {
			lib, fam, prov string
			names          []string
			weak           map[string]bool
		}
		var groups []*group
		index := map[[2]string]*group{}
		for _, n := range o.needs {
			prov := l.edges[key][n.Name]
			if prov == "" {
				for _, k := range l.order {
					if filepath.Base(k) == n.Name || l.objs[k].soname == n.Name {
						prov = k
						break
					}
				}
			}
			for _, d := range n.Needs {
				fam, _ := splitVer(d.Dep)
				g := index[[2]string{n.Name, fam}]
				if g == nil {
					g = &group{lib: n.Name, fam: fam, prov: prov, weak: map[string]bool{}}
					index[[2]string{n.Name, fam}] = g
					groups = append(groups, g)
				}
				g.names = append(g.names, d.Dep)
				if d.Flags&elf.VER_FLG_WEAK != 0 {
					g.weak[d.Dep] = true
				}
			}
		}
		for _, g := range groups {
			if g.prov == "" {
				continue
			}
			defs := l.objs[g.prov].defs
			r := row{obj: key, lib: g.lib, prov: g.prov, fam: g.fam}
			var reqV, haveV []string
			for _, n := range g.names {
				_, v := splitVer(n)
				reqV = append(reqV, v)
				if !defs[n] {
					if g.weak[n] {
						r.weak = append(r.weak, n)
					} else {
						r.missing = append(r.missing, n)
					}
				}
			}
			for n := range defs {
				if f, v := splitVer(n); f == g.fam {
					haveV = append(haveV, v)
				}
			}
			r.need, r.have = maxVer(reqV), maxVer(haveV)
			sort.Slice(r.missing, func(i, j int) bool {
				_, a := splitVer(r.missing[i])
				_, b := splitVer(r.missing[j])
				return cmpVer(a, b) > 0
			})
			rows = append(rows, r)
		}
	}
	return rows
}

func kernelVersion() [3]uint32 {
	var v [3]uint32
	b, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	if m := kernRe.FindStringSubmatch(strings.TrimSpace(string(b))); m != nil {
		for i := range v {
			n, _ := strconv.Atoi(m[i+1])
			v[i] = uint32(n)
		}
	}
	return v
}

func dotted(v [3]uint32) string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

func shortList(names []string) string {
	if len(names) <= 3 {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(names[:3], ", "), len(names)-3)
}

func tag(status string) string {
	text := map[string]string{"OK": "[ OK ]", "FAIL": "[FAIL]", "WARN": "[WARN]", "INFO": "[INFO]"}[status]
	if !useColor {
		return text
	}
	code := map[string]string{"OK": "32", "FAIL": "31", "WARN": "33", "INFO": "36"}[status]
	return "\033[" + code + "m" + text + "\033[0m"
}

func bold(s string) string {
	if useColor {
		return "\033[1m" + s + "\033[0m"
	}
	return s
}

type line struct {
	status, label, detail string
	sub                   []string
}

func machineName(m elf.Machine) string {
	return strings.ToLower(strings.TrimPrefix(m.String(), "EM_"))
}

func check(w io.Writer, path string, verbose bool, extra []string) int {
	main, err := openObject(path)
	if err != nil {
		var fe *elf.FormatError
		if errors.As(err, &fe) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			err = fmt.Errorf("not a valid ELF file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
		return 2
	}
	l := newLoader(main, extra)
	defer l.close()
	l.load(main, nil)

	base := filepath.Base
	bits := 32
	if main.f.Class == elf.ELFCLASS64 {
		bits = 64
	}
	kernel := kernelVersion()
	fmt.Fprintln(w, bold(fmt.Sprintf("%s: ELF%d %s %s", path, bits, machineName(main.f.Machine), main.kind())))
	fmt.Fprintf(w, "host: %s, Linux %s\n\n", runtime.GOARCH, dotted(kernel))

	var lines []line
	var reasons []string

	hm, known := hostMachine[runtime.GOARCH]
	okArch := !known || main.f.Machine == hm ||
		(hm == elf.EM_X86_64 && main.f.Machine == elf.EM_386) ||
		(hm == elf.EM_AARCH64 && main.f.Machine == elf.EM_ARM)
	if okArch {
		lines = append(lines, line{"OK", "arch", machineName(main.f.Machine), nil})
	} else {
		lines = append(lines, line{"FAIL", "arch", fmt.Sprintf("binary is %s, host is %s", machineName(main.f.Machine), runtime.GOARCH), nil})
		reasons = append(reasons, fmt.Sprintf("architecture mismatch: binary %s vs host %s", machineName(main.f.Machine), runtime.GOARCH))
	}

	switch {
	case main.interp != "":
		if _, err := os.Stat(main.interp); err == nil {
			lines = append(lines, line{"OK", "interpreter", main.interp, nil})
		} else {
			lines = append(lines, line{"FAIL", "interpreter", main.interp + " does not exist on this host", nil})
			reasons = append(reasons, fmt.Sprintf("dynamic loader %s is missing (wrong libc flavour or architecture?)", main.interp))
		}
	case len(main.needed) == 0:
		lines = append(lines, line{"INFO", "interpreter", "none (statically linked)", nil})
	}

	if abi, ok := main.abiTag(); ok {
		detail := fmt.Sprintf("needs >= %s, running %s", dotted(abi), dotted(kernel))
		if abi[0] < kernel[0] || (abi[0] == kernel[0] && (abi[1] < kernel[1] || (abi[1] == kernel[1] && abi[2] <= kernel[2]))) {
			lines = append(lines, line{"OK", "kernel", detail, nil})
		} else {
			lines = append(lines, line{"FAIL", "kernel", detail, nil})
			reasons = append(reasons, "kernel too old: "+detail)
		}
	}

	if len(main.needed) > 0 || len(l.objs) > 1 {
		byName := map[string]map[string]bool{}
		for _, m := range l.missing {
			if byName[m.name] == nil {
				byName[m.name] = map[string]bool{}
			}
			byName[m.name][base(m.by.path)] = true
		}
		var names []string
		for n := range byName {
			names = append(names, n)
		}
		sort.Strings(names)
		var sub []string
		for _, n := range names {
			var by []string
			for r := range byName[n] {
				by = append(by, r)
			}
			sort.Strings(by)
			sub = append(sub, fmt.Sprintf("%s  (needed by %s)", n, strings.Join(by, ", ")))
		}
		if verbose {
			for _, k := range l.order[1:] {
				sub = append(sub, fmt.Sprintf("%s  <-  %s", base(k), k))
			}
		}
		detail := fmt.Sprintf("%d loaded, %d missing", len(l.objs)-1, len(names))
		if len(names) > 0 {
			lines = append(lines, line{"FAIL", "libraries", detail, sub})
			reasons = append(reasons, "missing libraries: "+strings.Join(names, ", "))
		} else {
			lines = append(lines, line{"OK", "libraries", detail, sub})
		}
	}

	rows := l.versionRows()
	if len(rows) > 0 {
		var shown []row
		anyBad, anyWeak := false, false
		for _, r := range rows {
			anyBad = anyBad || len(r.missing) > 0
			anyWeak = anyWeak || len(r.weak) > 0
			if r.obj == l.mainKey || len(r.missing) > 0 || len(r.weak) > 0 || verbose {
				shown = append(shown, r)
			}
			if len(r.missing) > 0 {
				reasons = append(reasons, fmt.Sprintf("%s needs %s from %s, but this host provides only up to %s",
					base(r.obj), shortList(r.missing), r.lib, orDash(r.have)))
			}
		}
		sort.SliceStable(shown, func(i, j int) bool {
			a, b := shown[i], shown[j]
			if (a.obj == l.mainKey) != (b.obj == l.mainKey) {
				return a.obj == l.mainKey
			}
			if a.obj != b.obj {
				return a.obj < b.obj
			}
			if a.lib != b.lib {
				return a.lib < b.lib
			}
			return a.fam < b.fam
		})
		w := 0
		for _, r := range shown {
			if len(r.fam) > w {
				w = len(r.fam)
			}
		}
		var sub []string
		var lastObj, lastLib string
		for i, r := range shown {
			if i == 0 || r.obj != lastObj || r.lib != lastLib {
				lastObj, lastLib = r.obj, r.lib
				prefix := ""
				if r.obj != l.mainKey {
					prefix = "[" + base(r.obj) + "] "
				}
				sub = append(sub, fmt.Sprintf("%s%s  (%s)", prefix, r.lib, r.prov))
			}
			st := "OK"
			if len(r.missing) > 0 {
				st = "FAIL"
			} else if len(r.weak) > 0 {
				st = "WARN"
			}
			var body string
			if r.need != "" {
				body = fmt.Sprintf("%-*s need %-8s host %-8s", w, r.fam, r.need, orDash(r.have))
			} else if st == "FAIL" {
				body = fmt.Sprintf("%-*s absent", w, r.fam)
			} else {
				body = fmt.Sprintf("%-*s present", w, r.fam)
			}
			if len(r.missing) > 0 {
				body += "   missing " + shortList(r.missing)
			} else if len(r.weak) > 0 {
				body += "   weak, absent: " + shortList(r.weak)
			}
			sub = append(sub, "  "+tag(st)+" "+strings.TrimRight(body, " "))
		}
		status := "OK"
		if anyBad {
			status = "FAIL"
		} else if anyWeak {
			status = "WARN"
		}
		lines = append(lines, line{status, "versions", fmt.Sprintf("%d symbol-version families checked", len(rows)), sub})
	}

	anyWarn := false
	for _, ln := range lines {
		anyWarn = anyWarn || ln.status == "WARN"
		fmt.Fprintf(w, "%s %-12s %s\n", tag(ln.status), ln.label, ln.detail)
		for _, s := range ln.sub {
			fmt.Fprintln(w, "       "+s)
		}
	}

	verb := "LOAD"
	if main.runnable() {
		verb = "RUN"
	}
	fmt.Fprintln(w)
	if len(reasons) > 0 {
		fmt.Fprintln(w, bold("RESULT: CANNOT "+verb))
		for _, r := range reasons {
			fmt.Fprintln(w, "  - "+r)
		}
		return 1
	}
	suffix := ""
	if anyWarn {
		suffix = " (with warnings)"
	}
	fmt.Fprintln(w, bold("RESULT: CAN "+verb+suffix))
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ":") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// version is set at release time with -ldflags "-X main.version=...".
var version = "dev"

func versionString() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

func main() {
	var libPaths multiFlag
	verbose := flag.Bool("v", false, "also list every loaded library and every checked version family")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Var(&libPaths, "L", "extra library search `dir` (like LD_LIBRARY_PATH); repeatable")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "usage: libcheck [-v] [-L dir]... FILE...\nCheck whether an ELF program can run on this host.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println("libcheck " + versionString())
		return
	}
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if fi, err := os.Stdout.Stat(); err == nil {
		useColor = (fi.Mode()&os.ModeCharDevice != 0 || os.Getenv("FORCE_COLOR") != "") && os.Getenv("NO_COLOR") == ""
	}
	rc := 0
	for i, f := range flag.Args() {
		if i > 0 {
			fmt.Println()
		}
		if r := check(os.Stdout, f, *verbose, libPaths); r > rc {
			rc = r
		}
	}
	os.Exit(rc)
}
