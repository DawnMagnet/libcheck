package main

import (
	"debug/elf"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
)

var hostMachine = map[string]elf.Machine{
	"amd64": elf.EM_X86_64, "386": elf.EM_386, "arm64": elf.EM_AARCH64,
	"arm": elf.EM_ARM, "ppc64le": elf.EM_PPC64, "ppc64": elf.EM_PPC64,
	"s390x": elf.EM_S390, "riscv64": elf.EM_RISCV, "loong64": elf.EM_LOONGARCH,
}

type verdict int

const (
	canRun       verdict = iota // everything the loader needs is present
	cannotRun                   // something is missing that cannot simply be installed
	afterInstall                // runs once extra libraries are installed on a base-image target
)

type line struct {
	status, label, detail string
	sub                   []string
}

type versionRow struct {
	obj, lib, prov, fam, need, have string
	missing, weak                   []string
}

// report is the outcome of checking one program against one system.
type report struct {
	path     string
	kind     string
	header   []string
	target   *Profile
	runnable bool
	lines    []line
	reasons  []string // why the program cannot run
	extra    []string // libraries a base-image target would still need
	fails    []string // short per-family failures, for the summary table
	warn     bool
}

func (r *report) verdict() verdict {
	switch {
	case len(r.reasons) > 0:
		return cannotRun
	case len(r.extra) > 0:
		return afterInstall
	}
	return canRun
}

type options struct {
	verbose bool
	extra   []string
}

// analyze checks main against this host (prof == nil) or against a target profile.
func analyze(main *object, prof *Profile, opts options) *report {
	l := newLoader(main, prof, opts.extra)
	defer l.close()
	l.run()

	r := &report{path: main.path, target: prof, runnable: main.runnable()}
	bits := 32
	if main.class == elf.ELFCLASS64 {
		bits = 64
	}
	arch := archOf(main.machine, main.order)
	if arch == "" {
		arch = machineName(main.machine)
	}
	r.kind = fmt.Sprintf("ELF%d %s %s", bits, machineName(main.machine), main.kind())
	if prof == nil {
		r.header = []string{fmt.Sprintf("host: %s, Linux %s", runtime.GOARCH, dotted(kernelVersion()))}
	} else {
		r.header = []string{"target: " + prof.describe(), "        " + profileSummary(prof)}
	}
	add := func(status, label, detail string, sub ...string) {
		r.lines = append(r.lines, line{status, label, detail, sub})
	}
	fail := func(format string, a ...any) { r.reasons = append(r.reasons, fmt.Sprintf(format, a...)) }

	r.checkArch(main, prof, arch, add, fail)

	switch {
	case main.interp != "":
		if l.hasPath(main.interp) {
			add("OK", "interpreter", main.interp)
		} else {
			add("FAIL", "interpreter", main.interp+" does not exist")
			fail("dynamic loader %s is missing (wrong libc flavour or architecture?)", main.interp)
		}
	case len(main.needed) == 0:
		add("INFO", "interpreter", "none (statically linked)")
	}

	if abi, ok := main.abiTag(); ok {
		r.checkKernel(abi, prof, add, fail)
	}

	if len(main.needed) > 0 || len(l.objs) > 1 {
		r.checkLibraries(l, prof, opts.verbose, add, fail)
	}
	r.checkVersions(l, prof != nil, opts.verbose, add, fail)

	for _, ln := range r.lines {
		r.warn = r.warn || ln.status == "WARN"
	}
	return r
}

func profileSummary(p *Profile) string {
	parts := []string{"glibc " + orDash(p.glibc()), "libstdc++ " + orDash(p.libstdcxx())}
	if p.Kernel != "" {
		parts = append(parts, "kernel "+p.Kernel)
	}
	s := strings.Join(parts, ", ")
	var notes []string
	if !p.Complete {
		notes = append(notes, "base image")
	}
	if p.Image != "" {
		image, _, _ := strings.Cut(p.Image, "@")
		notes = append(notes, image)
	}
	if p.Generated != "" {
		notes = append(notes, "snapshot "+p.Generated)
	}
	if len(notes) > 0 {
		s += " (" + strings.Join(notes, ", ") + ")"
	}
	return s
}

type addFunc func(status, label, detail string, sub ...string)

func (r *report) checkArch(main *object, prof *Profile, arch string, add addFunc, fail func(string, ...any)) {
	name := arch
	if prof != nil {
		if arch == prof.Arch {
			add("OK", "arch", name)
			return
		}
		add("FAIL", "arch", fmt.Sprintf("binary is %s, target is %s", name, prof.Arch))
		fail("architecture mismatch: binary %s vs target %s", name, prof.Arch)
		return
	}
	hm, known := hostMachine[runtime.GOARCH]
	if !known || main.machine == hm ||
		(hm == elf.EM_X86_64 && main.machine == elf.EM_386) ||
		(hm == elf.EM_AARCH64 && main.machine == elf.EM_ARM) {
		add("OK", "arch", name)
		return
	}
	add("FAIL", "arch", fmt.Sprintf("binary is %s, host is %s", name, runtime.GOARCH))
	fail("architecture mismatch: binary %s vs host %s", name, runtime.GOARCH)
}

func (r *report) checkKernel(abi [3]uint32, prof *Profile, add addFunc, fail func(string, ...any)) {
	need := dotted(abi)
	if prof == nil {
		run := kernelVersion()
		detail := fmt.Sprintf("needs >= %s, running %s", need, dotted(run))
		if kernelLess(run, abi) {
			add("FAIL", "kernel", detail)
			fail("kernel too old: %s", detail)
		} else {
			add("OK", "kernel", detail)
		}
		return
	}
	tk, ok := parseKernel(prof.Kernel)
	if !ok {
		add("INFO", "kernel", fmt.Sprintf("needs >= %s (target kernel unknown)", need))
		return
	}
	have := prof.Kernel
	detail := fmt.Sprintf("needs >= %s, target ships %s", need, have)
	if prof.Complete {
		detail = fmt.Sprintf("needs >= %s, target runs %s", need, have)
	}
	switch {
	case !kernelLess(tk, abi):
		add("OK", "kernel", detail)
	case prof.Complete:
		add("FAIL", "kernel", detail)
		fail("kernel too old: %s", detail)
	default:
		add("WARN", "kernel", detail+" (newer kernels may be installed)")
	}
}

func (r *report) checkLibraries(l *loader, prof *Profile, verbose bool, add addFunc, fail func(string, ...any)) {
	byName := map[string]map[string]bool{}
	for _, m := range l.missing {
		if byName[m.name] == nil {
			byName[m.name] = map[string]bool{}
		}
		byName[m.name][baseName(m.by.path)] = true
	}
	var names []string
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	var sub []string
	for _, n := range names {
		var by []string
		for b := range byName[n] {
			by = append(by, b)
		}
		sort.Strings(by)
		sub = append(sub, fmt.Sprintf("%s  (needed by %s)", n, strings.Join(by, ", ")))
	}
	if verbose {
		for _, k := range l.order[1:] {
			sub = append(sub, fmt.Sprintf("%s  <-  %s", baseName(l.objs[k].path), l.objs[k].path))
		}
	}
	loaded := len(l.objs) - 1
	switch {
	case len(names) == 0:
		add("OK", "libraries", fmt.Sprintf("%d loaded, 0 missing", loaded), sub...)
	case prof != nil && !prof.Complete:
		add("WARN", "libraries", fmt.Sprintf("%d loaded, %d not in the base image", loaded, len(names)), sub...)
		r.extra = names
	default:
		add("FAIL", "libraries", fmt.Sprintf("%d loaded, %d missing", loaded, len(names)), sub...)
		fail("missing libraries: %s", strings.Join(names, ", "))
	}
}

func (r *report) checkVersions(l *loader, targeted, verbose bool, add addFunc, fail func(string, ...any)) {
	system, who := "host", "this host"
	if targeted {
		system, who = "target", "the target"
	}
	rows := versionRows(l)
	if len(rows) == 0 {
		return
	}
	mainKey := l.main.key
	var shown []versionRow
	anyBad, anyWeak := false, false
	for _, vr := range rows {
		anyBad = anyBad || len(vr.missing) > 0
		anyWeak = anyWeak || len(vr.weak) > 0
		if vr.obj == mainKey || len(vr.missing) > 0 || len(vr.weak) > 0 || verbose {
			shown = append(shown, vr)
		}
		if len(vr.missing) > 0 {
			_, top := splitVer(vr.missing[0])
			r.fails = append(r.fails, fmt.Sprintf("%s needs %s, has %s", vr.fam, orDash(top), orDash(vr.have)))
			fail("%s needs %s from %s, but %s provides only up to %s",
				baseName(l.objs[vr.obj].path), shortList(vr.missing), vr.lib, who, orDash(vr.have))
		}
	}
	sort.Strings(r.fails)
	sort.SliceStable(shown, func(i, j int) bool {
		a, b := shown[i], shown[j]
		if (a.obj == mainKey) != (b.obj == mainKey) {
			return a.obj == mainKey
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
	for _, vr := range shown {
		w = max(w, len(vr.fam))
	}
	var sub []string
	var lastObj, lastLib string
	for i, vr := range shown {
		if i == 0 || vr.obj != lastObj || vr.lib != lastLib {
			lastObj, lastLib = vr.obj, vr.lib
			prefix := ""
			if vr.obj != mainKey {
				prefix = "[" + baseName(l.objs[vr.obj].path) + "] "
			}
			sub = append(sub, fmt.Sprintf("%s%s  (%s)", prefix, vr.lib, l.objs[vr.prov].path))
		}
		st := "OK"
		switch {
		case len(vr.missing) > 0:
			st = "FAIL"
		case len(vr.weak) > 0:
			st = "WARN"
		}
		var body string
		switch {
		case vr.need != "":
			body = fmt.Sprintf("%-*s need %-8s %s %-8s", w, vr.fam, vr.need, system, orDash(vr.have))
		case st == "FAIL":
			body = fmt.Sprintf("%-*s absent", w, vr.fam)
		default:
			body = fmt.Sprintf("%-*s present", w, vr.fam)
		}
		if len(vr.missing) > 0 {
			body += "   missing " + shortList(vr.missing)
		} else if len(vr.weak) > 0 {
			body += "   weak, absent: " + shortList(vr.weak)
		}
		sub = append(sub, "  "+tag(st)+" "+strings.TrimRight(body, " "))
	}
	status := "OK"
	switch {
	case anyBad:
		status = "FAIL"
	case anyWeak:
		status = "WARN"
	}
	add(status, "versions", fmt.Sprintf("%d symbol-version families checked", len(rows)), sub...)
}

func versionRows(l *loader) []versionRow {
	var rows []versionRow
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
					if l.objs[k].soname == n.Name || baseName(l.objs[k].path) == n.Name {
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
			vr := versionRow{obj: key, lib: g.lib, prov: g.prov, fam: g.fam}
			var reqV, haveV []string
			for _, n := range g.names {
				_, v := splitVer(n)
				reqV = append(reqV, v)
				if !defs[n] {
					if g.weak[n] {
						vr.weak = append(vr.weak, n)
					} else {
						vr.missing = append(vr.missing, n)
					}
				}
			}
			for n := range defs {
				if f, v := splitVer(n); f == g.fam {
					haveV = append(haveV, v)
				}
			}
			vr.need, vr.have = maxVer(reqV), maxVer(haveV)
			sort.Slice(vr.missing, func(i, j int) bool {
				_, a := splitVer(vr.missing[i])
				_, b := splitVer(vr.missing[j])
				return cmpVer(a, b) > 0
			})
			rows = append(rows, vr)
		}
	}
	return rows
}

func shortList(names []string) string {
	if len(names) <= 3 {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(names[:3], ", "), len(names)-3)
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, "/"+string(os.PathSeparator)); i >= 0 {
		return p[i+1:]
	}
	return p
}
