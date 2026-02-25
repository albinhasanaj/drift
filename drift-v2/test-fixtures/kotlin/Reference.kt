// EXPECT: function_count=7 class_count=2 import_count=2

import java.io.File
import com.google.gson.Gson

// Pattern: camelCase naming convention

fun calculateTotal(items: List<Int>): Int {
    return items.sum()
}

fun validateInput(input: String): Boolean {
    if (input.isBlank()) {
        return false
    }
    return true
}

private fun formatOutput(data: Map<String, Any>): String {
    return Gson().toJson(data)
}

fun loadConfig(path: String): Map<String, Any> {
    val content = File(path).readText()
    return Gson().fromJson(content, Map::class.java) as Map<String, Any>
}

fun processItems(items: List<String>): List<String> {
    val validated = items.filter { validateInput(it) }
    return validated.map { formatOutput(mapOf("value" to it)) }
}

class DataProcessor(private val items: List<String>) {
    fun process(): List<String> {
        return processItems(items)
    }

    fun getTotal(): Int {
        return calculateTotal(items.map { it.length })
    }
}

class ConfigManager(private val configPath: String) {
    fun load(): Map<String, Any> {
        val fullPath = "${System.getProperty("user.dir")}/$configPath"
        return loadConfig(fullPath)
    }
}
