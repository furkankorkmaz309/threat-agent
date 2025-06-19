package models

type URLhaus struct {
	URL        string `json:"url"`
	URLStatus  string `json:"url_status"`
	Threat     string `json:"threat"`
	LastOnline string `json:"last_online"`
	Reporter   string `json:"reporter"`
}
