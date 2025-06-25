package db

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

func InitDB() (*sql.DB, error) {

	folderName := "../../../datas"
	err := os.MkdirAll(folderName, 0755)
	if err != nil {
		return nil, fmt.Errorf("an error occurred while creating directory : %v", err)
	}
	filename := folderName + "/data.db"

	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return nil, fmt.Errorf("an error occurred while creating database")
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("an error occurred while connecting database")
	}

	queryCVE := `CREATE TABLE IF NOT EXISTS cve(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	cve_id TEXT UNIQUE,
	published TEXT,
	last_modified TEXT,
	description TEXT,
	cvss TEXT,
	base_score DOUBLE,
	base_severity TEXT
	)`
	// cwes TEXT

	_, err = db.Exec(queryCVE)
	if err != nil {
		return nil, fmt.Errorf("an error occurred while creating CVE table")
	}

	queryURLhaus := `CREATE TABLE IF NOT EXISTS urlhaus(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	urlhaus_id TEXT UNIQUE,
	date_added TEXT,
	url TEXT,
	url_status TEXT,
	last_online TEXT,
	threat TEXT,
	tags TEXT,
	urlhaus_link TEXT,
	reporter TEXT
	)`
	// cwes TEXT

	_, err = db.Exec(queryURLhaus)
	if err != nil {
		return nil, fmt.Errorf("an error occurred while creating URLhaus table")
	}

	return db, nil
}
