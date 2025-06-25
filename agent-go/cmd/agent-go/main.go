package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/furkankorkmaz309/threat-agent/internal/fileops"
)

func main() {
	slog.Info("Feeds Updating...")

	CVEApiKey := ""
	err := fileops.Update(CVEApiKey, time.Now())
	if err != nil {
		slog.Error(err.Error())
		return
	}

	slog.Info("Feeds Updated.")
	fmt.Println()
}
