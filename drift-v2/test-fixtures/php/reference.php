<?php
// EXPECT: function_count=7 class_count=2 import_count=2

use App\Utils\FileHelper;
use App\Config\ConfigLoader;

// Pattern: camelCase naming convention

function calculateTotal(array $items): int {
    return array_sum($items);
}

function validateInput(string $input): bool {
    if (empty(trim($input))) {
        return false;
    }
    return true;
}

function formatOutput(array $data): string {
    return json_encode($data, JSON_PRETTY_PRINT);
}

function loadConfig(string $path): array {
    $content = file_get_contents($path);
    return json_decode($content, true);
}

function processItems(array $items): array {
    $validated = array_filter($items, fn($item) => validateInput($item));
    return array_map(fn($item) => formatOutput(['value' => $item]), $validated);
}

class DataProcessor {
    private array $items;

    public function __construct(array $initialItems) {
        $this->items = $initialItems;
    }

    public function process(): array {
        return processItems($this->items);
    }

    public function getTotal(): int {
        return calculateTotal(array_map(fn($i) => strlen($i), $this->items));
    }
}

class ConfigManager {
    private string $configPath;

    public function __construct(string $configPath) {
        $this->configPath = $configPath;
    }

    public function load(): array {
        $fullPath = getcwd() . '/' . $this->configPath;
        return loadConfig($fullPath);
    }
}
