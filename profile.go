package main

import (
	"bufio"
	"compress/gzip"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
)

const profileSchema = 1

// embeddedProfiles holds the built-in target profiles, one gzip-compressed
// JSON file per distribution and architecture: <id>.<arch>.json.gz.
//
//go:embed all:profiles/data
var embeddedProfiles embed.FS

const embeddedDir = "profiles/data"

// Profile describes the shared libraries a system provides. Profiles are
// created by "libcheck snapshot" and let libcheck judge a program against a
// system other than the one it runs on.
type Profile struct {
	Schema    int            `json:"schema"`
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Family    string         `json:"family,omitempty"`
	Image     string         `json:"image,omitempty"`
	Arch      string         `json:"arch"`
	Kernel    string         `json:"kernel,omitempty"`
	Complete  bool           `json:"complete,omitempty"`
	Generated string         `json:"generated,omitempty"`
	Dirs      []string       `json:"dirs"`
	Objects   []profObj      `json:"objects"`
	Paths     map[string]int `json:"paths"`
}

type profObj struct {
	Soname  string   `json:"soname,omitempty"`
	Class   int      `json:"class"`
	Machine uint16   `json:"machine"`
	Needed  []string `json:"needed,omitempty"`
	Defs    []string `json:"defs,omitempty"`
	Rpath   string   `json:"rpath,omitempty"`
	Runpath string   `json:"runpath,omitempty"`
}

// provided returns the highest version of a symbol-version family (for
// example GLIBC) that the library with the given soname defines.
func (p *Profile) provided(soname, family string) string {
	best := ""
	for _, o := range p.Objects {
		if o.Soname != soname {
			continue
		}
		for _, d := range o.Defs {
			if f, v := splitVer(d); f == family && v != "" && (best == "" || cmpVer(v, best) > 0) {
				best = v
			}
		}
	}
	return best
}

func (p *Profile) glibc() string     { return p.provided("libc.so.6", "GLIBC") }
func (p *Profile) libstdcxx() string { return p.provided("libstdc++.so.6", "GLIBCXX") }
func (p *Profile) describe() string  { return fmt.Sprintf("%s [%s, %s]", p.Name, p.ID, p.Arch) }
func (p *Profile) validate() error {
	switch {
	case p.Schema != profileSchema:
		return fmt.Errorf("unsupported profile schema %d (this build reads %d)", p.Schema, profileSchema)
	case p.ID == "" || p.Arch == "":
		return errors.New("profile has no id or arch")
	}
	for _, i := range p.Paths {
		if i < 0 || i >= len(p.Objects) {
			return errors.New("profile refers to an unknown object")
		}
	}
	return nil
}

func writeProfile(w io.Writer, p *Profile, compress bool) error {
	if compress {
		zw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
		if err != nil {
			return err
		}
		if err := json.NewEncoder(zw).Encode(p); err != nil {
			return err
		}
		return zw.Close()
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(p)
}

func readProfile(r io.Reader) (*Profile, error) {
	br := bufio.NewReader(r)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return decodeProfile(zr)
	}
	return decodeProfile(br)
}

func decodeProfile(r io.Reader) (*Profile, error) {
	var p Profile
	if err := json.NewDecoder(r).Decode(&p); err != nil {
		return nil, err
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func loadProfileFile(name string) (*Profile, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	p, err := readProfile(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return p, nil
}

// profileRef names one profile file inside a profile directory.
type profileRef struct{ ID, Arch, File string }

func listProfiles(fsys fs.FS, dir string) []profileRef {
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil
	}
	var refs []profileRef
	for _, e := range ents {
		stem, ok := strings.CutSuffix(e.Name(), ".json.gz")
		if !ok {
			continue
		}
		dot := strings.LastIndex(stem, ".")
		if dot <= 0 {
			continue
		}
		refs = append(refs, profileRef{ID: stem[:dot], Arch: stem[dot+1:], File: path.Join(dir, e.Name())})
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].ID != refs[j].ID {
			return refs[i].ID < refs[j].ID
		}
		return refs[i].Arch < refs[j].Arch
	})
	return refs
}

func loadProfileRef(fsys fs.FS, ref profileRef) (*Profile, error) {
	f, err := fsys.Open(ref.File)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	p, err := readProfile(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref.File, err)
	}
	return p, nil
}

func isProfileFile(spec string) bool {
	return strings.Contains(spec, "/") || strings.HasSuffix(spec, ".json") || strings.HasSuffix(spec, ".gz")
}

// resolveTargets turns --target arguments into profiles for the given
// architecture. A spec is a profile id, a glob such as "ubuntu-*", the word
// "all", or the path of a profile file.
func resolveTargets(fsys fs.FS, dir string, specs []string, arch string) ([]*Profile, error) {
	refs := listProfiles(fsys, dir)
	var out []*Profile
	seen := map[string]bool{}
	add := func(p *Profile) {
		if k := p.ID + "/" + p.Arch; !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	for _, spec := range specs {
		if isProfileFile(spec) {
			p, err := loadProfileFile(spec)
			if err != nil {
				return nil, err
			}
			add(p)
			continue
		}
		pattern, glob := spec, strings.ContainsAny(spec, "*?[")
		if spec == "all" {
			pattern, glob = "*", true
		}
		var ids, arches []string
		matched := 0
		for _, ref := range refs {
			if ok, err := path.Match(pattern, ref.ID); err != nil {
				return nil, fmt.Errorf("bad target pattern %q: %w", spec, err)
			} else if !ok {
				continue
			}
			ids = append(ids, ref.ID)
			if ref.Arch != arch {
				arches = append(arches, ref.Arch)
				continue
			}
			p, err := loadProfileRef(fsys, ref)
			if err != nil {
				return nil, err
			}
			add(p)
			matched++
		}
		switch {
		case len(ids) == 0:
			return nil, fmt.Errorf("unknown target %q (run \"libcheck targets\" to list them)", spec)
		case matched == 0 && !glob:
			return nil, fmt.Errorf("target %q has no %s profile (available: %s)", spec, arch, strings.Join(arches, ", "))
		case matched == 0:
			return nil, fmt.Errorf("no %s profile matches %q", arch, spec)
		}
	}
	return out, nil
}
