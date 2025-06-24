package fileops

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/furkankorkmaz309/threat-agent/app"
	"github.com/furkankorkmaz309/threat-agent/db"
	"github.com/furkankorkmaz309/threat-agent/fetch"
)

func Update(CVEApiKey string, ts time.Time) error {
	// cve
	db, err := db.InitDB()
	if err != nil {
		return err
	}
	defer db.Close()

	app := &app.App{
		DB: db,
	}

	cveList, cveTimeElapsed, err := fetch.FetchCVE(CVEApiKey, app)
	if err != nil {
		return err
	}

	/*
		err = saveToFile(ts, "cves_latest.json", cveList)
		if err != nil {
			return err
		}
	*/

	infoStr := fmt.Sprintf("Total %v CVE saved successfully %.2f ms", cveList, float64(cveTimeElapsed.Microseconds())/1000)
	slog.Info(infoStr)

	return nil
}
