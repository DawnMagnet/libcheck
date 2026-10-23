package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

var useColor bool

var statusColor = map[string]string{"OK": "32", "FAIL": "31", "WARN": "33", "INFO": "36"}

func tag(status string) string {
	text := map[string]string{"OK": "[ OK ]", "FAIL": "[FAIL]", "WARN": "[WARN]", "INFO": "[INFO]"}[status]
	return colorize(status, text)
}

func colorize(status, text string) string {
	if !useColor {
		return text
	}
	return "\033[" + statusColor[status] + "m" + text + "\033[0m"
}

func bold(s string) string {
	if useColor {
		return "\033[1m" + s + "\033[0m"
	}
	return s
}

func printReport(w io.Writer, r *report) {
	fmt.Fprintln(w, bold(r.path+": "+r.kind))
	for _, h := range r.header {
		fmt.Fprintln(w, h)
	}
	fmt.Fprintln(w)
	for _, ln := range r.lines {
		fmt.Fprintf(w, "%s %-12s %s\n", tag(ln.status), ln.label, ln.detail)
		for _, s := range ln.sub {
			fmt.Fprintln(w, "       "+s)
		}
	}

	verb := "LOAD"
	if r.runnable {
		verb = "RUN"
	}
	fmt.Fprintln(w)
	switch r.verdict() {
	case cannotRun:
		fmt.Fprintln(w, bold("RESULT: CANNOT "+verb))
		for _, reason := range r.reasons {
			fmt.Fprintln(w, "  - "+reason)
		}
	case afterInstall:
		fmt.Fprintln(w, bold("RESULT: CAN "+verb+" AFTER INSTALLING "+strings.Join(r.extra, ", ")))
	default:
		suffix := ""
		if r.warn {
			suffix = " (with warnings)"
		}
		fmt.Fprintln(w, bold("RESULT: CAN "+verb+suffix))
	}
}

// printMatrix prints one row per target for the same program.
func printMatrix(w io.Writer, reps []*report) {
	first := reps[0]
	fmt.Fprintln(w, bold(first.path+": "+first.kind))
	fmt.Fprintln(w)

	type row struct {
		id, glibc, cxx, result, status, detail string
	}
	rows := make([]row, 0, len(reps))
	ok := 0
	for _, r := range reps {
		rw := row{id: r.target.ID, glibc: orDash(r.target.glibc()), cxx: orDash(r.target.libstdcxx())}
		switch r.verdict() {
		case canRun:
			rw.result, rw.status = "CAN RUN", "OK"
			ok++
		case afterInstall:
			rw.result, rw.status = "AFTER INSTALL", "WARN"
			rw.detail = strings.Join(r.extra, ", ")
		default:
			rw.result, rw.status = "CANNOT RUN", "FAIL"
			rw.detail = strings.Join(r.fails, "; ")
			if rw.detail == "" {
				rw.detail = r.reasons[0]
			}
		}
		rows = append(rows, rw)
	}
	widths := [4]int{len("TARGET"), len("GLIBC"), len("LIBSTDC++"), len("RESULT")}
	for _, rw := range rows {
		widths[0] = max(widths[0], len(rw.id))
		widths[1] = max(widths[1], len(rw.glibc))
		widths[2] = max(widths[2], len(rw.cxx))
		widths[3] = max(widths[3], len(rw.result))
	}
	fmt.Fprintf(w, "%s\n", bold(fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %s", widths[0], "TARGET", widths[1], "GLIBC",
		widths[2], "LIBSTDC++", widths[3], "RESULT", "DETAIL")))
	for _, rw := range rows {
		fmt.Fprintf(w, "%-*s  %-*s  %-*s  %s%s  %s\n", widths[0], rw.id, widths[1], rw.glibc, widths[2], rw.cxx,
			colorize(rw.status, rw.result), strings.Repeat(" ", widths[3]-len(rw.result)), rw.detail)
	}
	fmt.Fprintf(w, "\n%s\n", bold(fmt.Sprintf("%d of %d targets can run it", ok, len(rows))))
}

// printTargets lists the available target profiles, one row per distribution.
func printTargets(w io.Writer, profiles []*Profile) {
	type entry struct {
		p      *Profile
		arches []string
	}
	byID := map[string]*entry{}
	var ids []string
	for _, p := range profiles {
		e := byID[p.ID]
		if e == nil {
			e = &entry{p: p}
			byID[p.ID] = e
			ids = append(ids, p.ID)
		}
		e.arches = append(e.arches, p.Arch)
		if p.Arch == "amd64" {
			e.p = p
		}
	}
	sort.Strings(ids)
	head := []string{"ID", "NAME", "ARCH", "GLIBC", "LIBSTDC++", "KERNEL", "SNAPSHOT"}
	table := [][]string{head}
	for _, id := range ids {
		e := byID[id]
		sort.Strings(e.arches)
		table = append(table, []string{id, e.p.Name, strings.Join(e.arches, ","), orDash(e.p.glibc()),
			orDash(e.p.libstdcxx()), orDash(e.p.Kernel), orDash(e.p.Generated)})
	}
	widths := make([]int, len(head))
	for _, row := range table {
		for i, c := range row {
			widths[i] = max(widths[i], len(c))
		}
	}
	for i, row := range table {
		var sb strings.Builder
		for j, c := range row {
			if j == len(row)-1 {
				sb.WriteString(c)
			} else {
				fmt.Fprintf(&sb, "%-*s  ", widths[j], c)
			}
		}
		if i == 0 {
			fmt.Fprintln(w, bold(sb.String()))
		} else {
			fmt.Fprintln(w, sb.String())
		}
	}
}
