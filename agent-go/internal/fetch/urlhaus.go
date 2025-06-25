package fetch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/models"
)

func FetchURLhaus(app *app.App) (string, error) {
	start := time.Now()

	url := "https://urlhaus.abuse.ch/downloads/json_recent/"

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("an error occurred while sending the request : %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("an error occurred while reading response : %v", err)
	}

	var rawData map[string][]models.URLhausResponse
	err = json.Unmarshal(body, &rawData)
	if err != nil {
		return "", fmt.Errorf("an error occurred while parsing JSON : %v", err)
	}

	query := `INSERT OR IGNORE INTO urlhaus(urlhaus_id, date_added, url, url_status, last_online, threat, tags, urlhaus_link, reporter) VALUES (?,?,?,?,?,?,?,?,?)`
	var total int
	var startVal int
	queryStart := `SELECT COUNT(*) FROM urlhaus`
	err = app.DB.QueryRow(queryStart).Scan(&startVal)
	if err != nil {
		return "", fmt.Errorf("an error occurred while counting query : %v", err)
	}

	tx, err := app.DB.Begin()
	if err != nil {
		return "", fmt.Errorf("an error occurred while starting transaction : %v", err)
	}

	stmt, err := tx.Prepare(query)
	if err != nil {
		tx.Rollback()
		return "", fmt.Errorf("an error occurred while preparing statement : %v", err)
	}
	defer stmt.Close()

	for key, list := range rawData {
		for _, item := range list {
			tagsStr := strings.Join(item.Tags, ",")

			_, err := stmt.Exec(key, item.Dateadded, item.URL, item.URLStatus, item.LastOnline, item.Threat, tagsStr, item.UrlhausLink, item.Reporter)
			if err != nil {
				tx.Rollback()
				return "", fmt.Errorf("an error occurred while inserting to database : %v", err)
			}
		}
	}

	err = tx.Commit()
	if err != nil {
		return "", fmt.Errorf("an error occurred while commiting transaction : %v", err)
	}

	var endVal int
	queryEnd := `SELECT COUNT(*) FROM urlhaus`
	err = app.DB.QueryRow(queryEnd).Scan(&endVal)
	if err != nil {
		return "", fmt.Errorf("an error occurred while counting query : %v", err)
	}
	total = endVal - startVal

	elapsedAllEntries := time.Since(start)
	infoStr := fmt.Sprintf("Total %v Threat Feed saved successfully in %.2f ms", total, float64(elapsedAllEntries.Microseconds())/1000)

	return infoStr, nil
}
