package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/furkankorkmaz309/threat-agent/fileops"
)

func main() {
	slog.Info("Feeds Updating...")

	CVEApiKey := "be7c24bd-4d29-4867-9e20-d5c8c07b8e17  "
	err := fileops.Update(CVEApiKey, time.Now())
	if err != nil {
		slog.Error(err.Error())
		return
	}

	slog.Info("Feeds Updated.")
	fmt.Println()
}
