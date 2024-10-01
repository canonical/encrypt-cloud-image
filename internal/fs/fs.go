package fs

import (
	"fmt"
	"os"
	"regexp"
	"strconv"

	internal_exec "github.com/canonical/encrypt-cloud-image/internal/exec"
	log "github.com/sirupsen/logrus"
)

var (
	blockCountPatternRe = regexp.MustCompile(`Block count: *([0-9]*)`)
	blockSizePatternRe  = regexp.MustCompile(`Block size: *([0-9]*)`)
)

func GetBlockInfo(devPath string) (uint64, uint64, error) {
	log.Infoln("get filesystem info for ", devPath)

	cmd := internal_exec.LoggedCommand("tune2fs",
		"-l",
		devPath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, 0, err
	}

	matches := blockCountPatternRe.FindSubmatch(output)
	if len(matches) < 2 {
		return 0, 0, fmt.Errorf("unable to determine block count for filesystem on %s", devPath)
	}

	blockCount, err := strconv.Atoi(string(matches[1]))
	if err != nil {
		return 0, 0, err
	}

	matches = blockSizePatternRe.FindSubmatch(output)
	if len(matches) < 2 {
		return 0, 0, fmt.Errorf("unable to determine block size for filesystem on %s", devPath)
	}

	blockSize, err := strconv.Atoi(string(matches[1]))
	if err != nil {
		return 0, 0, err
	}

	return uint64(blockCount), uint64(blockSize), nil
}

func PathIsBlockDevice(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("cannot obtain source file information: %w", err)
	}

	return fi.Mode()&os.ModeDevice != 0, nil
}
