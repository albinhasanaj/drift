// EXPECT: function_count=7 class_count=2 import_count=2

use std::collections::HashMap;
use std::fs;

// Pattern: snake_case naming convention

pub fn calculate_total(items: &[i32]) -> i32 {
    items.iter().sum()
}

pub fn validate_input(input: &str) -> bool {
    !input.trim().is_empty()
}

fn format_output(data: &HashMap<String, String>) -> String {
    serde_json::to_string_pretty(data).unwrap_or_default()
}

pub fn load_config(path: &str) -> Result<HashMap<String, String>, std::io::Error> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content).unwrap_or_default())
}

pub fn process_items(items: &[String]) -> Vec<String> {
    items
        .iter()
        .filter(|item| validate_input(item))
        .map(|item| {
            let mut data = HashMap::new();
            data.insert("value".to_string(), item.clone());
            format_output(&data)
        })
        .collect()
}

pub struct DataProcessor {
    items: Vec<String>,
}

impl DataProcessor {
    pub fn new(items: Vec<String>) -> Self {
        Self { items }
    }

    pub fn process(&self) -> Vec<String> {
        process_items(&self.items)
    }

    pub fn get_total(&self) -> i32 {
        let lengths: Vec<i32> = self.items.iter().map(|i| i.len() as i32).collect();
        calculate_total(&lengths)
    }
}

pub struct ConfigManager {
    config_path: String,
}

impl ConfigManager {
    pub fn new(config_path: String) -> Self {
        Self { config_path }
    }

    pub fn load(&self) -> Result<HashMap<String, String>, std::io::Error> {
        load_config(&self.config_path)
    }
}
