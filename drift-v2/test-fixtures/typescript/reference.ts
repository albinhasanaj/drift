// EXPECT: function_count=7 class_count=2 import_count=2

import { readFile } from "fs/promises";
import { join } from "path";

// Pattern: camelCase naming convention
export function calculateTotal(items: number[]): number {
  return items.reduce((sum, item) => sum + item, 0);
}

export function validateInput(input: string): boolean {
  if (!input || input.trim().length === 0) {
    return false;
  }
  return true;
}

function formatOutput(data: Record<string, unknown>): string {
  return JSON.stringify(data, null, 2);
}

async function loadConfig(path: string): Promise<Record<string, unknown>> {
  const content = await readFile(path, "utf-8");
  return JSON.parse(content);
}

function processItems(items: string[]): string[] {
  const validated = items.filter((item) => validateInput(item));
  return validated.map((item) => formatOutput({ value: item }));
}

export class DataProcessor {
  private items: string[] = [];

  constructor(initialItems: string[]) {
    this.items = initialItems;
  }

  process(): string[] {
    return processItems(this.items);
  }

  getTotal(): number {
    return calculateTotal(this.items.map((i) => i.length));
  }
}

export class ConfigManager {
  private configPath: string;

  constructor(configPath: string) {
    this.configPath = configPath;
  }

  async load(): Promise<Record<string, unknown>> {
    const fullPath = join(process.cwd(), this.configPath);
    return loadConfig(fullPath);
  }
}
