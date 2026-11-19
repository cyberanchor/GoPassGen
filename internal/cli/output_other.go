//go:build !unix

package cli

import (
	"io/fs"
	"os"
)

func copyOwner(*os.File, fs.FileInfo) {}
