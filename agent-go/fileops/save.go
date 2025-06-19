package fileops

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func saveToFile[T any](ts time.Time, filename string, values []T) error {
	timestamp := ts.Format("2006-01-02_15-04-05")

	folderName := fmt.Sprintf("../datas/data-%s", timestamp)
	err := os.MkdirAll(folderName, 0755)

	if err != nil {
		return fmt.Errorf("an error occurred while creating directory : %v", err)
	}

	file, err := os.Create(folderName + "/" + filename)
	if err != nil {
		return fmt.Errorf("an error occurred while creating file : %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", " ")
	err = encoder.Encode(values)
	if err != nil {
		return fmt.Errorf("an error occurred while encoding values : %v", err)
	}

	return nil
}
