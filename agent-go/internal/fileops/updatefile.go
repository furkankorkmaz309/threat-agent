package fileops

import (
	"log/slog"
	"time"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/db"
	"github.com/furkankorkmaz309/threat-agent/internal/fetch"
)

func Update(CVEApiKey string, ts time.Time) error {
	db, err := db.InitDB()
	if err != nil {
		return err
	}
	defer db.Close()

	app := &app.App{
		DB: db,
	}

	infoStr, err := fetch.FetchCVE(CVEApiKey, app)
	if err != nil {
		return err
	}
	slog.Info(infoStr)

	infoStr, err = fetch.FetchURLhaus(app)
	if err != nil {
		return err
	}
	slog.Info(infoStr)

	return nil
}
