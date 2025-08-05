package fetch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/models"
)

func FetchCVE(apiKey string, app *app.App) (string, error) {
	now := time.Now().UTC()
	start := now.Add(-240 * time.Hour)

	const layout = "2006-01-02T15:04:05.000"

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&pubStartDate=%s&pubEndDate=%s", start.Format(layout), now.Format(layout))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("an error occurred while creating the request : %v", err)
	}
	req.Header.Set("apiKey", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("an error occurred while sending the request : %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("CVE request failed with status : %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("an error occurred while reading the response body : %v", err)
	}

	if len(body) == 0 {
		return "", fmt.Errorf("CVE body is empty")
	}

	// fmt.Println(string(body))

	var startVal int
	queryStart := `SELECT COUNT(*) FROM cve`
	err = app.DB.QueryRow(queryStart).Scan(&startVal)
	if err != nil {
		return "", fmt.Errorf("an error occurred while counting query : %v", err)
	}

	var result models.CVEList
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("an error occured while parsing JSON : %v", err)
	}
	if len(result.Vulnerabilities) == 0 {
		infostr := "No new CVE Entries found"
		return infostr, nil
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
			return "", fmt.Errorf("an error occurred while inserting to database : %v", err)
		}
	}

	var endVal int
	queryEnd := `SELECT COUNT(*) FROM cve`
	err = app.DB.QueryRow(queryEnd).Scan(&endVal)
	if err != nil {
		return "", fmt.Errorf("an error occurred while counting query : %v", err)
	}
	total = endVal - startVal

	elapsed := time.Since(now)

	infoStr := fmt.Sprintf("Total %v CVE saved successfully in %.2f ms", total, float64(elapsed.Microseconds())/1000)
	return infoStr, nil
}
