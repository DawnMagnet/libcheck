// libcheck reports whether an ELF program can run on this host, or on a
// target system such as Debian 12 or RHEL 9.
//
// It resolves every DT_NEEDED library the way ld.so does and checks each
// required symbol version (GLIBC_x.y, GLIBCXX_x.y, CXXABI_x.y, ...) against the
// versions the system's libraries define. Static analysis only: dlopen()ed
// libraries and data files are not checked.
//
// Exit status: 0 = can run, 1 = cannot run, 2 = usage or input error,
// 3 = can run once extra libraries are installed on a base-image target.
package main

import (
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func run(args []string, stdout, stderr io.Writer) int {
	setColor(stdout)
	if len(args) > 0 {
		switch args[0] {
		case "targets":
			return cmdTargets(args[1:], stdout, stderr)
		case "snapshot":
			return cmdSnapshot(args[1:], stdout, stderr)
		case "help":
			usage(stdout)
			return 0
		}
	}
	return cmdCheck(args, stdout, stderr)
}

func setColor(w io.Writer) {
	useColor = false
	if os.Getenv("NO_COLOR") != "" {
		return
	}
	if os.Getenv("FORCE_COLOR") != "" {
		useColor = true
		return
	}
	if f, ok := w.(*os.File); ok {
		if fi, err := f.Stat(); err == nil {
			useColor = fi.Mode()&os.ModeCharDevice != 0
		}
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  libcheck [flags] FILE...     check whether programs can run on this host or a target
  libcheck targets             list the built-in target systems
  libcheck snapshot [flags]    record a system's libraries as a target profile

Flags for checking:
`)
	newCheckFlags(w).fs.PrintDefaults()
}

type checkFlags struct {
	fs          *flag.FlagSet
	verbose     *bool
	showVersion *bool
	targets     multiFlag
	libPaths    multiFlag
}

func newCheckFlags(out io.Writer) *checkFlags {
	c := &checkFlags{fs: flag.NewFlagSet("libcheck", flag.ContinueOnError)}
	c.fs.SetOutput(out)
	c.verbose = c.fs.Bool("v", false, "also list every loaded library and every checked version family")
	c.showVersion = c.fs.Bool("version", false, "print version and exit")
	c.fs.Var(&c.targets, "t", "check against a target system instead of this host (shorthand for -target)")
	c.fs.Var(&c.targets, "target", "target system: an id such as debian-12, a glob such as 'ubuntu-*',\n\t\"all\", or a profile file; repeatable")
	c.fs.Var(&c.libPaths, "L", "extra library search `dir` (like LD_LIBRARY_PATH); repeatable")
	return c
}

// parseInterleaved parses flags that may appear before, between or after file names.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var files []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return files, nil
		}
		files = append(files, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func combineExit(codes ...int) int {
	has := map[int]bool{}
	for _, c := range codes {
		has[c] = true
	}
	for _, c := range []int{2, 1, 3} {
		if has[c] {
			return c
		}
	}
	return 0
}

func exitCode(v verdict) int {
	switch v {
	case cannotRun:
		return 1
	case afterInstall:
		return 3
	}
	return 0
}

func cmdCheck(args []string, stdout, stderr io.Writer) int {
	cf := newCheckFlags(stderr)
	cf.fs.Usage = func() { usage(stderr) }
	files, err := parseInterleaved(cf.fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *cf.showVersion {
		fmt.Fprintln(stdout, "libcheck "+versionString())
		return 0
	}
	if len(files) == 0 {
		usage(stderr)
		return 2
	}
	if len(cf.targets) == 0 && runtime.GOOS != "linux" {
		fmt.Fprintf(stderr, "libcheck: checking the local system needs Linux; use -target to check against a built-in system\n")
		return 2
	}
	opts := options{verbose: *cf.verbose, extra: cf.libPaths}
	codes := make([]int, 0, len(files))
	for i, f := range files {
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		codes = append(codes, checkFile(stdout, stderr, f, cf.targets, opts))
	}
	return combineExit(codes...)
}

func checkFile(stdout, stderr io.Writer, file string, targets []string, opts options) int {
	main, err := openObject(file)
	if err != nil {
		var fe *elf.FormatError
		if errors.As(err, &fe) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			err = fmt.Errorf("not a valid ELF file: %w", err)
		}
		fmt.Fprintf(stderr, "%s: %v\n", file, err)
		return 2
	}
	defer main.close()

	if len(targets) == 0 {
		rep := analyze(main, nil, opts)
		printReport(stdout, rep)
		return exitCode(rep.verdict())
	}

	arch := archOf(main.machine, main.order)
	if arch == "" {
		fmt.Fprintf(stderr, "%s: no target profiles exist for %s binaries\n", file, machineName(main.machine))
		return 2
	}
	profs, err := resolveTargets(embeddedProfiles, embeddedDir, targets, arch)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", file, err)
		return 2
	}
	reps := make([]*report, 0, len(profs))
	codes := make([]int, 0, len(profs))
	for _, p := range profs {
		rep := analyze(main, p, opts)
		reps = append(reps, rep)
		codes = append(codes, exitCode(rep.verdict()))
	}
	if len(reps) == 1 {
		printReport(stdout, reps[0])
	} else {
		if opts.verbose {
			for _, rep := range reps {
				printReport(stdout, rep)
				fmt.Fprintln(stdout)
			}
		}
		printMatrix(stdout, reps)
	}
	return combineExit(codes...)
}

func cmdTargets(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("libcheck targets", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	refs := listProfiles(embeddedProfiles, embeddedDir)
	if len(refs) == 0 {
		fmt.Fprintln(stderr, "libcheck: this build has no built-in targets; create one with \"libcheck snapshot\"")
		return 1
	}
	profs := make([]*Profile, 0, len(refs))
	for _, ref := range refs {
		p, err := loadProfileRef(embeddedProfiles, ref)
		if err != nil {
			fmt.Fprintf(stderr, "libcheck: %v\n", err)
			return 2
		}
		profs = append(profs, p)
	}
	printTargets(stdout, profs)
	return 0
}

func cmdSnapshot(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("libcheck snapshot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o snapshotOpts
	out := fs.String("o", "", "write the profile to `file` (gzip-compressed when it ends in .gz); default: stdout")
	fs.StringVar(&o.Root, "root", "/", "snapshot the file system tree under `dir`")
	fs.StringVar(&o.ID, "id", "", "profile id, such as debian-12 (default: derived from os-release)")
	fs.StringVar(&o.Name, "name", "", "display name (default: PRETTY_NAME from os-release)")
	fs.StringVar(&o.Image, "image", "", "container image the tree was taken from, for the record")
	fs.StringVar(&o.Kernel, "kernel", "", "kernel version the system ships (default: the running kernel when -root is /)")
	fs.StringVar(&o.Arch, "arch", "", "architecture, such as amd64 (default: detected from the libraries)")
	fs.BoolVar(&o.Complete, "complete", true, "the tree is a full system; set to false for a minimal base image,\n\twhere missing libraries only mean \"install more packages\"")
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: libcheck snapshot [flags]\nRecord the shared libraries of a system as a profile for libcheck -target.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	p, err := snapshot(o)
	if err != nil {
		fmt.Fprintf(stderr, "libcheck: %v\n", err)
		return 2
	}
	if err := writeSnapshot(stdout, *out, p); err != nil {
		fmt.Fprintf(stderr, "libcheck: %v\n", err)
		return 2
	}
	fmt.Fprintf(stderr, "libcheck: recorded %s: %d libraries, %s\n", p.describe(), len(p.Objects), profileSummary(p))
	return 0
}

// writeSnapshot writes p to the named file (gzip-compressed when the name ends
// in .gz), or to stdout when name is empty or "-".
func writeSnapshot(stdout io.Writer, name string, p *Profile) error {
	if name == "" || name == "-" {
		return writeProfile(stdout, p, false)
	}
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	err = writeProfile(f, p, strings.HasSuffix(name, ".gz"))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
