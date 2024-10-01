package fs

import (
	"fmt"
	"os"
	"regexp"
	"strconv"

	internal_exec "github.com/canonical/encrypt-cloud-image/internal/exec"
	log "github.com/sirupsen/logrus"
)

const (
	BlockSize = 4096
)

var (
	blockCountPatternRe = regexp.MustCompile(`Block count: *([0-9]*)`)
)

func GetBlockCount(devPath string) (uint64, error) {
	log.Infoln("calculate filesystem block count on", devPath)

	cmd := internal_exec.LoggedCommand("tune2fs",
		"-l",
		devPath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, err
	}

	matches := blockCountPatternRe.FindSubmatch(output)
	if len(matches) < 2 {
		return 0, fmt.Errorf("unable to determine block size for filesystem on %s", devPath)
	}

	blockCount, err := strconv.Atoi(string(matches[1]))
	if err != nil {
		return 0, err
	}

	return uint64(blockCount), nil
}

func PathIsBlockDevice(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("cannot obtain source file information: %w", err)
	}

	return fi.Mode()&os.ModeDevice != 0, nil
}
