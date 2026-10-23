package main

import (
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
)

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

var verRe = regexp.MustCompile(`^(.*?)_(\d+(?:\.\d+)*)$`)

// splitVer splits "GLIBC_2.34" into ("GLIBC", "2.34"). Names without a
// numeric suffix, such as "GLIBC_PRIVATE", come back whole with an empty version.
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

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
