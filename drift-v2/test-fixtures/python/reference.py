# EXPECT: function_count=7 class_count=2 import_count=2

import json
from pathlib import Path

# Pattern: snake_case naming convention


def calculate_total(items: list[int]) -> int:
    return sum(items)


def validate_input(input_str: str) -> bool:
    if not input_str or not input_str.strip():
        return False
    return True


def format_output(data: dict) -> str:
    return json.dumps(data, indent=2)


def load_config(config_path: str) -> dict:
    content = Path(config_path).read_text()
    return json.loads(content)


def process_items(items: list[str]) -> list[str]:
    validated = [item for item in items if validate_input(item)]
    return [format_output({"value": item}) for item in validated]


class DataProcessor:
    def __init__(self, initial_items: list[str]):
        self.items = initial_items

    def process(self) -> list[str]:
        return process_items(self.items)

    def get_total(self) -> int:
        return calculate_total([len(i) for i in self.items])


class ConfigManager:
    def __init__(self, config_path: str):
        self.config_path = config_path

    def load(self) -> dict:
        full_path = Path.cwd() / self.config_path
        return load_config(str(full_path))
