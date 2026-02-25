// EXPECT: function_count=7 class_count=2 import_count=2

import java.util.List;
import java.util.stream.Collectors;

// Pattern: camelCase naming convention
public class Reference {

    public static int calculateTotal(List<Integer> items) {
        return items.stream().mapToInt(Integer::intValue).sum();
    }

    public static boolean validateInput(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false;
        }
        return true;
    }

    private static String formatOutput(Object data) {
        return data.toString();
    }

    public static String loadConfig(String path) throws Exception {
        return new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path)));
    }

    public static List<String> processItems(List<String> items) {
        List<String> validated = items.stream()
            .filter(item -> validateInput(item))
            .collect(Collectors.toList());
        return validated.stream()
            .map(item -> formatOutput(item))
            .collect(Collectors.toList());
    }
}

class DataProcessor {
    private List<String> items;

    public DataProcessor(List<String> initialItems) {
        this.items = initialItems;
    }

    public List<String> process() {
        return Reference.processItems(this.items);
    }

    public int getTotal() {
        return Reference.calculateTotal(
            this.items.stream().map(String::length).collect(Collectors.toList())
        );
    }
}
