package fetch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/furkankorkmaz309/threat-agent/app"
	"github.com/furkankorkmaz309/threat-agent/models"
)

func FetchCVE(apiKey string, app *app.App) (int, time.Duration, error) {
	now := time.Now().UTC()
	start := now.Add(-12 * time.Hour)

	const layout = "2006-01-02T15:04:05.000"

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&pubStartDate=%s&pubEndDate=%s", start.Format(layout), now.Format(layout))
	fmt.Println(url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("an error occurred while creating the request : %v", err)
	}
	req.Header.Set("apiKey", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("an error occurred while sending the request : %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, fmt.Errorf("an error occurred while reading the response body : %v", err)
	}

	if len(body) < 50 {
		return 0, 0, fmt.Errorf("an error occurred: response body looks like too short : %v", string(body))
	}

	var startVal int
	queryStart := `SELECT COUNT(*) FROM cve`
	err = app.DB.QueryRow(queryStart).Scan(&startVal)
	if err != nil {
		return 0, 0, fmt.Errorf("count query failed: %v", err)
	}

	var result models.CVEList
	err = json.Unmarshal(body, &result)
	if err != nil {
		return 0, 0, fmt.Errorf("an error occured while parsing JSON : %v", err)
	}
	if len(result.Vulnerabilities) == 0 {
		return 0, 0, fmt.Errorf("there is no cve")
	}

	query := `INSERT OR IGNORE INTO cve(cve_id, published, last_modified, description, cvss, base_score, base_severity) VALUES (?,?,?,?,?,?,?)`
	var total int

	for _, item := range result.Vulnerabilities {
		cve := item.CVE

		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		cvss := ""
		baseScore := 0.0
		baseSeverity := ""
		if len(cve.Metrics.CvssMetricV40) > 0 {
			cvss = "v4.0"
			baseScore = cve.Metrics.CvssMetricV40[0].CvssData.BaseScore
			baseSeverity = cve.Metrics.CvssMetricV40[0].CvssData.BaseSeverity
		} else if len(cve.Metrics.CvssMetricV31) > 0 {
			cvss = "v3.1"
			baseScore = cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
			baseSeverity = cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		} else if len(cve.Metrics.CvssMetricV30) > 0 {
			cvss = "v3.0"
			baseScore = cve.Metrics.CvssMetricV30[0].CvssData.BaseScore
			baseSeverity = cve.Metrics.CvssMetricV30[0].CvssData.BaseSeverity
		} else if len(cve.Metrics.CvssMetricV2) > 0 {
			cvss = "v2.0"
			baseScore = cve.Metrics.CvssMetricV2[0].CvssData.BaseScore
			baseSeverity = cve.Metrics.CvssMetricV2[0].BaseSeverity
		}

		_, err := app.DB.Exec(query, cve.ID, cve.Published, cve.LastModified, desc, cvss, baseScore, baseSeverity)
		if err != nil {
			return 0, 0, fmt.Errorf("DB insert error: %v", err)
		}
	}

	var endVal int
	queryEnd := `SELECT COUNT(*) FROM cve`
	err = app.DB.QueryRow(queryEnd).Scan(&endVal)
	if err != nil {
		return 0, 0, fmt.Errorf("count query failed: %v", err)
	}
	total = endVal - startVal

	elapsed := time.Since(now)
	return total, elapsed, nil
}
