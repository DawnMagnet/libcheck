package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// rootFS resolves absolute paths inside a directory tree as if it were the
// root of a file system, so symlinks such as /lib64 -> usr/lib64 and absolute
// link targets stay inside the tree.
type rootFS struct{ root string }

func (r rootFS) real(p string) (string, error) {
	const maxLinks = 40
	todo := strings.Split(p, "/")
	var cur []string
	links := 0
	for len(todo) > 0 {
		c := todo[0]
		todo = todo[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(cur) > 0 {
				cur = cur[:len(cur)-1]
			}
			continue
		}
		next := filepath.Join(r.root, filepath.Join(cur...), c)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			cur = append(cur, c)
			continue
		}
		if links++; links > maxLinks {
			return "", errors.New("too many levels of symbolic links")
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(target, "/") {
			cur = cur[:0]
		}
		todo = append(strings.Split(target, "/"), todo...)
	}
	return filepath.Join(r.root, filepath.Join(cur...)), nil
}

func (r rootFS) isDir(p string) bool {
	rp, err := r.real(p)
	if err != nil {
		return false
	}
	st, err := os.Stat(rp)
	return err == nil && st.IsDir()
}

// glob expands wildcards in the last element of an absolute path.
func (r rootFS) glob(pattern string) []string {
	dir, base := path.Split(pattern)
	rd, err := r.real(dir)
	if err != nil {
		return nil
	}
	matches, _ := filepath.Glob(filepath.Join(rd, base))
	sort.Strings(matches)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, path.Join(dir, filepath.Base(m)))
	}
	return out
}

// ldSearchDirs returns the directories the dynamic loader searches for
// libraries, in order: those listed in ld.so.conf, then the trusted defaults.
func ldSearchDirs(r rootFS) []string {
	var dirs []string
	var conf func(file string, depth int)
	conf = func(file string, depth int) {
		rp, err := r.real(file)
		if err != nil || depth > 8 {
			return
		}
		b, err := os.ReadFile(rp)
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(b), "\n") {
			line, _, _ = strings.Cut(line, "#")
			fields := strings.Fields(line)
			switch {
			case len(fields) == 0:
			case fields[0] == "include":
				for _, pat := range fields[1:] {
					if !path.IsAbs(pat) {
						pat = path.Join(path.Dir(file), pat)
					}
					for _, m := range r.glob(pat) {
						conf(m, depth+1)
					}
				}
			case strings.HasPrefix(fields[0], "/"):
				dirs = append(dirs, path.Clean(fields[0]))
			}
		}
	}
	conf("/etc/ld.so.conf", 0)
	dirs = append(dirs, "/lib64", "/usr/lib64", "/lib", "/usr/lib")
	dirs = append(dirs, r.glob("/lib/*-linux-gnu*")...)
	dirs = append(dirs, r.glob("/usr/lib/*-linux-gnu*")...)

	seen := map[string]bool{}
	var res []string
	for _, d := range dirs {
		if !seen[d] && r.isDir(d) {
			seen[d] = true
			res = append(res, d)
		}
	}
	return res
}

type snapshotOpts struct {
	Root, ID, Name, Family, Image, Kernel, Arch string
	Complete                                    bool
}

// snapshot records the shared libraries found in the loader search
// directories of the file system tree under o.Root.
func snapshot(o snapshotOpts) (*Profile, error) {
	root := filepath.Clean(o.Root)
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", o.Root)
	}
	fsr := rootFS{root}
	p := &Profile{
		Schema: profileSchema, ID: o.ID, Name: o.Name, Family: o.Family, Image: o.Image,
		Kernel: o.Kernel, Complete: o.Complete, Generated: time.Now().UTC().Format("2006-01-02"),
		Dirs: ldSearchDirs(fsr), Paths: map[string]int{},
	}
	osr := readOSRelease(fsr)
	if p.ID == "" {
		p.ID = strings.Trim(osr["ID"]+"-"+osr["VERSION_ID"], "-")
	}
	if p.Name == "" {
		p.Name = osr["PRETTY_NAME"]
	}
	if p.Family == "" {
		p.Family, _, _ = strings.Cut(osr["ID_LIKE"], " ")
		if p.Family == "" {
			p.Family = osr["ID"]
		}
	}
	if p.ID == "" {
		return nil, errors.New("cannot derive an id from /etc/os-release, pass one explicitly")
	}
	if p.Name == "" {
		p.Name = p.ID
	}

	byReal := map[string]int{}
	skip := map[string]bool{}
	archCount := map[string]int{}
	for _, dir := range p.Dirs {
		rd, err := fsr.real(dir)
		if err != nil {
			continue
		}
		ents, err := os.ReadDir(rd)
		if err != nil {
			continue
		}
		for _, e := range ents {
			logical := path.Join(dir, e.Name())
			rp, err := fsr.real(logical)
			if err != nil || skip[rp] {
				continue
			}
			idx, ok := byReal[rp]
			if !ok {
				obj := openLibrary(rp, e.Name())
				if obj == nil {
					skip[rp] = true
					continue
				}
				idx = len(p.Objects)
				byReal[rp] = idx
				p.Objects = append(p.Objects, toProfObj(obj))
				archCount[archOf(obj.machine, obj.order)]++
				obj.close()
			}
			p.Paths[logical] = idx
		}
	}
	if len(p.Objects) == 0 {
		return nil, fmt.Errorf("no shared libraries found under %s", o.Root)
	}

	p.Arch = o.Arch
	if p.Arch == "" {
		best := 0
		for a, n := range archCount {
			if n > best || (n == best && a < p.Arch) {
				p.Arch, best = a, n
			}
		}
	}
	if p.Kernel == "" && root == "/" && o.Complete {
		if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			if m := kernRe.FindString(strings.TrimSpace(string(b))); m != "" {
				p.Kernel = m
			}
		}
	}
	return p, nil
}

// openLibrary opens a shared library, or returns nil for anything else.
func openLibrary(realPath, name string) *object {
	st, err := os.Stat(realPath)
	if err != nil || !st.Mode().IsRegular() {
		return nil
	}
	obj, err := openObject(realPath)
	if err != nil {
		return nil
	}
	if obj.typ != elf.ET_DYN || !obj.dynamic || (obj.soname == "" && !strings.Contains(name, ".so")) {
		obj.close()
		return nil
	}
	return obj
}

func toProfObj(o *object) profObj {
	po := profObj{
		Soname: o.soname, Class: 32, Machine: uint16(o.machine),
		Needed: o.needed, Rpath: o.rpath, Runpath: o.runpath,
	}
	if o.class == elf.ELFCLASS64 {
		po.Class = 64
	}
	for d := range o.defs {
		po.Defs = append(po.Defs, d)
	}
	sort.Strings(po.Defs)
	return po
}

func readOSRelease(r rootFS) map[string]string {
	out := map[string]string{}
	for _, f := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		rp, err := r.real(f)
		if err != nil {
			continue
		}
		b, err := os.ReadFile(rp)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && !strings.HasPrefix(k, "#") {
				out[k] = strings.Trim(v, `"'`)
			}
		}
		break
	}
	return out
}
