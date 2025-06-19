package fetch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/furkankorkmaz309/threat-agent/models"
)

func FetchCVE(apiKey string) ([]models.CVEInfo, time.Duration, error) {
	now := time.Now().UTC()
	start := now.Add(-12 * time.Hour)

	const layout = "2006-01-02T15:04:05.000"

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&pubStartDate=%s&pubEndDate=%s", start.Format(layout), now.Format(layout))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("an error occurred while creating the request : %v", err)
	}
	req.Header.Set("apiKey", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("an error occurred while sending the request : %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("an error occurred while reading the response body : %v", err)
	}

	if len(body) < 50 {
		return nil, 0, fmt.Errorf("an error occurred: response body looks like too short : %v", string(body))
	}

	var result models.NVDResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, 0, fmt.Errorf("an error occured while parsing JSON : %v", err)
	}

	var cveInfos []models.CVEInfo
	for _, item := range result.Vulnerabilities {
		cve := item.CVE
		info := models.CVEInfo{
			ID:               cve.ID,
			CWEs:             []string{},
			PublishedDate:    cve.Published,
			LastModifiedDate: cve.LastModified,
		}

		for _, desc := range cve.Descriptions {
			if desc.Lang == "en" {
				info.Description = desc.Value
				break
			}
		}

		switch {
		case len(cve.Metrics.CVSSv31) > 0:
			info.BaseScore = cve.Metrics.CVSSv31[0].CVSSData.BaseScore
			info.Severity = cve.Metrics.CVSSv31[0].CVSSData.BaseSeverity
		case len(cve.Metrics.CVSSv30) > 0:
			info.BaseScore = cve.Metrics.CVSSv30[0].CVSSData.BaseScore
			info.Severity = cve.Metrics.CVSSv30[0].CVSSData.BaseSeverity
		case len(cve.Metrics.CVSSv2) > 0:
			info.BaseScore = cve.Metrics.CVSSv2[0].CVSSData.BaseScore
			info.Severity = cve.Metrics.CVSSv2[0].CVSSData.BaseSeverity
		default:
			info.BaseScore = -1
			info.Severity = "UNKNOWN"
		}

		for _, w := range cve.Weaknesses {
			for _, d := range w.Description {
				if d.Lang == "en" {
					info.CWEs = append(info.CWEs, d.Value)
				}
			}
		}

		cveInfos = append(cveInfos, info)
	}

	for i, j := 0, len(cveInfos)-1; i < j; i, j = i+1, j-1 {
		cveInfos[i], cveInfos[j] = cveInfos[j], cveInfos[i]
	}

	elapsed := time.Since(now)
	return cveInfos, elapsed, nil
}
