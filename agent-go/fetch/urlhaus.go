package fetch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/furkankorkmaz309/threat-agent/models"
)

func FetchURLhaus() ([]models.URLhaus, []models.URLhaus, time.Duration, time.Duration, error) {
	start := time.Now()

	url := "https://urlhaus.abuse.ch/downloads/json_recent/"

	resp, err := http.Get(url)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("an error occurred while sending the request : %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("an error occurred while reading response : %v", err)
	}

	var rawData map[string][]models.URLhaus
	err = json.Unmarshal(body, &rawData)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("an error occurred while parsing JSON : %v", err)
	}

	firstXValues := 100

	var allEntries []models.URLhaus
	for _, entries := range rawData {
		allEntries = append(allEntries, entries...)
	}

	for i, j := 0, len(allEntries)-1; i < j; i, j = i+1, j-1 {
		allEntries[i], allEntries[j] = allEntries[j], allEntries[i]
	}

	elapsedAllEntries := time.Since(start)

	var filtered []models.URLhaus
	for _, entry := range allEntries {
		if entry.URLStatus == "online" && entry.Threat == "malware_download" {
			filtered = append(filtered, entry)
		}
	}

	for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}

	elapsedFiltered := time.Since(start)

	allEntries = allEntries[:firstXValues]
	filtered = filtered[:firstXValues]

	return allEntries, filtered, elapsedAllEntries, elapsedFiltered, nil
}
