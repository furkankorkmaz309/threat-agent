package models

type URLhausResponse struct {
	Dateadded   string   `json:"dateadded"`
	URL         string   `json:"url"`
	URLStatus   string   `json:"url_status"`
	LastOnline  string   `json:"last_online"`
	Threat      string   `json:"threat"`
	Tags        []string `json:"tags"`
	UrlhausLink string   `json:"urlhaus_link"`
	Reporter    string   `json:"reporter"`
}
