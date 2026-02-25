// EXPECT: function_count=7 class_count=2 import_count=2

package reference

import (
	"encoding/json"
	"os"
)

// Pattern: camelCase for unexported, PascalCase for exported

func CalculateTotal(items []int) int {
	total := 0
	for _, item := range items {
		total += item
	}
	return total
}

func ValidateInput(input string) bool {
	if len(input) == 0 {
		return false
	}
	return true
}

func formatOutput(data interface{}) string {
	bytes, _ := json.MarshalIndent(data, "", "  ")
	return string(bytes)
}

func LoadConfig(path string) (map[string]interface{}, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	err = json.Unmarshal(content, &result)
	return result, err
}

func ProcessItems(items []string) []string {
	var result []string
	for _, item := range items {
		if ValidateInput(item) {
			result = append(result, formatOutput(map[string]string{"value": item}))
		}
	}
	return result
}

type DataProcessor struct {
	items []string
}

func NewDataProcessor(items []string) *DataProcessor {
	return &DataProcessor{items: items}
}

func (dp *DataProcessor) Process() []string {
	return ProcessItems(dp.items)
}

type ConfigManager struct {
	configPath string
}

func (cm *ConfigManager) Load() (map[string]interface{}, error) {
	return LoadConfig(cm.configPath)
}
