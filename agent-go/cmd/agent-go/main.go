package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/furkankorkmaz309/threat-agent/internal/fileops"
	"github.com/joho/godotenv"
)

func main() {
	slog.Info("Feeds Updating...")

	err := godotenv.Load("../../../.env")
	if err != nil {
		slog.Error("No .env file found")
		return
	}

	CVEApiKey := os.Getenv("CVE_KEY")
	if CVEApiKey == "" {
		slog.Error("cve key is empty")
		return
	}

	err = fileops.Update(CVEApiKey)
	if err != nil {
		slog.Error(err.Error())
		return
	}

	slog.Info("Feeds Updated.")
	fmt.Println()
}
