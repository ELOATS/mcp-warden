//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package report

import "os"

func ttyColumns(*os.File) int { return 0 }
