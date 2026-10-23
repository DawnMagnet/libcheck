package main

import (
	"debug/elf"
	"encoding/binary"
	"path/filepath"
	"strings"
)

// object is a parsed ELF file, or a library taken from a target profile.
type object struct {
	key     string // identity used to deduplicate loaded libraries
	path    string // path shown to the user
	origin  string // directory that $ORIGIN expands to
	typ     elf.Type
	class   elf.Class
	machine elf.Machine
	order   binary.ByteOrder
	dynamic bool
	needed  []string
	soname  string
	rpath   string
	runpath string
	interp  string
	needs   []elf.DynamicVersionNeed
	defs    map[string]bool
	f       *elf.File // nil for objects that come from a target profile
}

func openObject(path string) (*object, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	o := &object{
		key: realpath(path), path: path, origin: filepath.Dir(realpath(path)),
		typ: f.Type, class: f.Class, machine: f.Machine, order: f.ByteOrder,
		dynamic: f.SectionByType(elf.SHT_DYNAMIC) != nil, defs: map[string]bool{}, f: f,
	}
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

func (o *object) close() {
	if o.f != nil {
		o.f.Close()
	}
}

func (o *object) runnable() bool { return o.typ == elf.ET_EXEC || o.interp != "" }

func (o *object) kind() string {
	switch {
	case !o.dynamic && o.interp == "":
		return "static executable"
	case o.typ == elf.ET_EXEC:
		return "executable"
	case o.interp != "":
		return "PIE executable"
	}
	return "shared object"
}

// abiTag returns the minimum kernel version from .note.ABI-tag.
func (o *object) abiTag() ([3]uint32, bool) {
	var v [3]uint32
	if o.f == nil {
		return v, false
	}
	s := o.f.Section(".note.ABI-tag")
	if s == nil {
		return v, false
	}
	d, err := s.Data()
	if err != nil || len(d) < 12 {
		return v, false
	}
	bo := o.order
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

// archOf maps an ELF object to the GOARCH-style names used by target profiles.
func archOf(m elf.Machine, bo binary.ByteOrder) string {
	switch m {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_386:
		return "386"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_RISCV:
		return "riscv64"
	case elf.EM_PPC64:
		if bo == binary.BigEndian {
			return "ppc64"
		}
		return "ppc64le"
	case elf.EM_S390:
		return "s390x"
	case elf.EM_LOONGARCH:
		return "loong64"
	}
	return ""
}

func machineName(m elf.Machine) string {
	return strings.ToLower(strings.TrimPrefix(m.String(), "EM_"))
}
