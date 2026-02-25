# EXPECT: function_count=7 class_count=2 import_count=2

require 'json'
require 'pathname'

# Pattern: snake_case naming convention

def calculate_total(items)
  items.sum
end

def validate_input(input)
  return false if input.nil? || input.strip.empty?
  true
end

def format_output(data)
  JSON.pretty_generate(data)
end

def load_config(path)
  content = File.read(path)
  JSON.parse(content)
end

def process_items(items)
  validated = items.select { |item| validate_input(item) }
  validated.map { |item| format_output({ value: item }) }
end

class DataProcessor
  def initialize(initial_items)
    @items = initial_items
  end

  def process
    process_items(@items)
  end

  def get_total
    calculate_total(@items.map(&:length))
  end
end

class ConfigManager
  def initialize(config_path)
    @config_path = config_path
  end

  def load
    full_path = Pathname.new(Dir.pwd).join(@config_path)
    load_config(full_path.to_s)
  end
end
