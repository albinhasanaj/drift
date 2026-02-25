// EXPECT: function_count=7 class_count=2 import_count=2

const fs = require("fs");
const path = require("path");

// Pattern: camelCase naming convention
function calculateTotal(items) {
  return items.reduce((sum, item) => sum + item, 0);
}

function validateInput(input) {
  if (!input || input.trim().length === 0) {
    return false;
  }
  return true;
}

function formatOutput(data) {
  return JSON.stringify(data, null, 2);
}

async function loadConfig(configPath) {
  const content = fs.readFileSync(configPath, "utf-8");
  return JSON.parse(content);
}

function processItems(items) {
  const validated = items.filter((item) => validateInput(item));
  return validated.map((item) => formatOutput({ value: item }));
}

class DataProcessor {
  constructor(initialItems) {
    this.items = initialItems;
  }

  process() {
    return processItems(this.items);
  }

  getTotal() {
    return calculateTotal(this.items.map((i) => i.length));
  }
}

class ConfigManager {
  constructor(configPath) {
    this.configPath = configPath;
  }

  async load() {
    const fullPath = path.join(process.cwd(), this.configPath);
    return loadConfig(fullPath);
  }
}

module.exports = { DataProcessor, ConfigManager, calculateTotal, validateInput };
