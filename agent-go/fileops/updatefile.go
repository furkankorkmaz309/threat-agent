package fileops

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/furkankorkmaz309/threat-agent/fetch"
)

func Update(CVEApiKey string, ts time.Time) error {
	// cve
	cveList, cveTimeElapsed, err := fetch.FetchCVE(CVEApiKey)
	if err != nil {
		return err
	}

	err = saveToFile(ts, "cves_latest.json", cveList)
	if err != nil {
		return err
	}

	infoStr := fmt.Sprintf("Total %v CVE saved successfully %.2f ms", len(cveList), float64(cveTimeElapsed.Microseconds())/1000)
	slog.Info(infoStr)

	//threat feed
	rssEntries, filtered, threatFeedElapsed, filteredThreatFeedElapsed, err := fetch.FetchURLhaus()
	if err != nil {
		return err
	}

	err = saveToFile(ts, "threat_feeds_latest.json", rssEntries)
	if err != nil {
		return err
	}

	infoStr = fmt.Sprintf("Total %v Threat Feed saved successfully %.2f ms", len(rssEntries), float64(threatFeedElapsed.Microseconds())/1000)
	slog.Info(infoStr)

	err = saveToFile(ts, "threat_feeds_filtered.json", filtered)
	if err != nil {
		return err
	}

	infoStr = fmt.Sprintf("Total %v Filtered Threat Feed saved successfully %.2f ms", len(filtered), float64(filteredThreatFeedElapsed.Microseconds())/1000)
	slog.Info(infoStr)
	return nil

}
