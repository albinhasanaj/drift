// EXPECT: function_count=7 class_count=2 import_count=2

using System.Linq;
using System.Text.Json;

// Pattern: PascalCase naming convention
public class Reference
{
    public static int CalculateTotal(List<int> items)
    {
        return items.Sum();
    }

    public static bool ValidateInput(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }
        return true;
    }

    private static string FormatOutput(object data)
    {
        return JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
    }

    public static string LoadConfig(string path)
    {
        return File.ReadAllText(path);
    }

    public static List<string> ProcessItems(List<string> items)
    {
        var validated = items.Where(item => ValidateInput(item)).ToList();
        return validated.Select(item => FormatOutput(new { Value = item })).ToList();
    }
}

public class DataProcessor
{
    private List<string> _items;

    public DataProcessor(List<string> initialItems)
    {
        _items = initialItems;
    }

    public List<string> Process()
    {
        return Reference.ProcessItems(_items);
    }

    public int GetTotal()
    {
        return Reference.CalculateTotal(_items.Select(i => i.Length).ToList());
    }
}
