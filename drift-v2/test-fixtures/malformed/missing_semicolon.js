// Malformed: missing semicolons (valid JS but tests parser tolerance)
const x = 1
const y = 2
function add(a, b) { return a + b }
const result = add(x y)  // syntax error: missing comma
