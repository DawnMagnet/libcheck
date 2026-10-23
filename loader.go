package main

import (
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	cacheRe = regexp.MustCompile(`(?m)^\s*(\S+) \(.*\) => (\S+)$`)
	kernRe  = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?`)

	platformName = map[string]string{
		"amd64": "x86_64", "386": "i686", "arm64": "aarch64", "arm": "armv7l",
	}
)

// searchDir is a directory in a library search path. Directories that are
// "real" are looked up on the local file system; the others are looked up in
// the target profile.
type searchDir struct {
	dir  string
	real bool
}

type missingRef struct {
	by   *object
	name string
}

// loader resolves the transitive library dependencies of a program the way
// ld.so does, either against this host or against a target profile.
type loader struct {
	main     *object
	prof     *Profile // nil: resolve against this host
	extra    []string
	cache    map[string][]string
	hostDirs []string
	envDirs  []string
	profObjs map[int]*object
	objs     map[string]*object
	order    []string
	edges    map[string]map[string]string // object key -> needed name -> provider key ("" = missing)
	missing  []missingRef
}

func newLoader(main *object, prof *Profile, extra []string) *loader {
	l := &loader{
		main: main, prof: prof, extra: extra,
		profObjs: map[int]*object{}, objs: map[string]*object{}, edges: map[string]map[string]string{},
	}
	if prof == nil {
		l.cache = ldCache()
		l.hostDirs = ldSearchDirs(rootFS{"/"})
		for _, p := range strings.Split(os.Getenv("LD_LIBRARY_PATH"), ":") {
			if p != "" {
				l.envDirs = append(l.envDirs, p)
			}
		}
	}
	l.objs[main.key] = main
	l.order = append(l.order, main.key)
	return l
}

func (l *loader) run() { l.load(l.main, nil) }

func (l *loader) close() {
	for _, o := range l.objs {
		if o != l.main {
			o.close()
		}
	}
}

func (l *loader) load(o *object, parent []searchDir) {
	chain := parent
	if o.rpath != "" && o.runpath == "" {
		chain = append(l.expand(o, o.rpath), parent...)
	}
	l.edges[o.key] = map[string]string{}
	for _, name := range o.needed {
		dep := l.find(name, o, chain)
		if dep == nil {
			l.missing = append(l.missing, missingRef{o, name})
			continue
		}
		l.edges[o.key][name] = dep.key
		if _, ok := l.objs[dep.key]; !ok {
			l.objs[dep.key] = dep
			l.order = append(l.order, dep.key)
			l.load(dep, chain)
		}
	}
}

// find follows the ld.so search order: RPATH, -L and LD_LIBRARY_PATH,
// RUNPATH, then the system library path.
func (l *loader) find(name string, o *object, chain []searchDir) *object {
	if strings.Contains(name, "/") {
		if l.prof == nil {
			return l.openReal(name)
		}
		return l.openProfile(path.Clean(name))
	}
	dirs := append([]searchDir{}, chain...)
	for _, d := range l.extra {
		dirs = append(dirs, searchDir{d, true})
	}
	for _, d := range l.envDirs {
		dirs = append(dirs, searchDir{d, true})
	}
	if o.runpath != "" {
		dirs = append(dirs, l.expand(o, o.runpath)...)
	}
	for _, sd := range dirs {
		var m *object
		if sd.real {
			m = l.openReal(filepath.Join(sd.dir, name))
		} else {
			m = l.openProfile(path.Join(sd.dir, name))
		}
		if m != nil {
			return m
		}
	}
	return l.system(name)
}

func (l *loader) system(name string) *object {
	if l.prof != nil {
		for _, d := range l.prof.Dirs {
			if m := l.openProfile(path.Join(d, name)); m != nil {
				return m
			}
		}
		return nil
	}
	for _, c := range l.cache[name] {
		if m := l.openReal(c); m != nil {
			return m
		}
	}
	for _, d := range l.hostDirs {
		if m := l.openReal(filepath.Join(d, name)); m != nil {
			return m
		}
	}
	return nil
}

func (l *loader) expand(o *object, spec string) []searchDir {
	lib := "lib"
	if o.class == elf.ELFCLASS64 {
		lib = "lib64"
	}
	arch := archOf(l.main.machine, l.main.order)
	plat, ok := platformName[arch]
	if !ok {
		plat = arch
	}
	var res []searchDir
	for _, e := range strings.Split(spec, ":") {
		r := strings.NewReplacer("${ORIGIN}", o.origin, "$ORIGIN", o.origin, "${LIB}", lib, "$LIB", lib,
			"${PLATFORM}", plat, "$PLATFORM", plat)
		if p := r.Replace(e); p != "" {
			real := l.prof == nil || (o.f != nil && strings.Contains(e, "ORIGIN"))
			res = append(res, searchDir{p, real})
		}
	}
	return res
}

// openReal opens p if it is an ELF with the same class and machine as the program.
func (l *loader) openReal(p string) *object {
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return nil
	}
	if o, ok := l.objs[realpath(p)]; ok {
		return o
	}
	o, err := openObject(p)
	if err != nil {
		return nil
	}
	if o.class != l.main.class || o.machine != l.main.machine {
		o.close()
		return nil
	}
	return o
}

func (l *loader) openProfile(p string) *object {
	idx, ok := l.prof.Paths[p]
	if !ok {
		return nil
	}
	if o, ok := l.profObjs[idx]; ok {
		return o
	}
	po := l.prof.Objects[idx]
	class := elf.ELFCLASS32
	if po.Class == 64 {
		class = elf.ELFCLASS64
	}
	if class != l.main.class || elf.Machine(po.Machine) != l.main.machine {
		return nil
	}
	o := &object{
		key: fmt.Sprintf("target:%d", idx), path: p, origin: path.Dir(p),
		typ: elf.ET_DYN, class: class, machine: elf.Machine(po.Machine), dynamic: true,
		needed: po.Needed, soname: po.Soname, rpath: po.Rpath, runpath: po.Runpath,
		defs: make(map[string]bool, len(po.Defs)),
	}
	for _, d := range po.Defs {
		o.defs[d] = true
	}
	l.profObjs[idx] = o
	return o
}

// hasPath reports whether the system being checked has a file at p.
func (l *loader) hasPath(p string) bool {
	if l.prof != nil {
		_, ok := l.prof.Paths[p]
		return ok
	}
	_, err := os.Stat(p)
	return err == nil
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

func parseKernel(s string) ([3]uint32, bool) {
	var v [3]uint32
	m := kernRe.FindStringSubmatch(s)
	if m == nil {
		return v, false
	}
	for i := range v {
		n, _ := strconv.Atoi(m[i+1])
		v[i] = uint32(n)
	}
	return v, true
}

func kernelLess(a, b [3]uint32) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func dotted(v [3]uint32) string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }
