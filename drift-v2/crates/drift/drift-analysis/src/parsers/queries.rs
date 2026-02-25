//! Pre-compiled tree-sitter Query objects per language.
//!
//! Each language gets 2 consolidated queries: structure (functions, classes, imports, exports)
//! and calls (call sites, decorators). Compiled once, reused across all files.

use tree_sitter::Query;

use crate::scanner::language_detect::Language;

/// Holds the two pre-compiled queries for a language.
pub struct CompiledQueries {
    /// Extracts functions, classes, imports, exports, properties.
    pub structure: Query,
    /// Extracts call sites, decorators, string/numeric literals, error handling.
    pub calls: Query,
}

/// Get the structure query S-expression for a language.
pub fn structure_query_for(lang: Language) -> &'static str {
    match lang {
        Language::TypeScript | Language::JavaScript => TS_JS_STRUCTURE_QUERY,
        Language::Python => PYTHON_STRUCTURE_QUERY,
        Language::Java => JAVA_STRUCTURE_QUERY,
        Language::CSharp => CSHARP_STRUCTURE_QUERY,
        Language::Go => GO_STRUCTURE_QUERY,
        Language::Rust => RUST_STRUCTURE_QUERY,
        Language::Ruby => RUBY_STRUCTURE_QUERY,
        Language::Php => PHP_STRUCTURE_QUERY,
        Language::Kotlin => KOTLIN_STRUCTURE_QUERY,
        Language::Cpp | Language::C => CSHARP_STRUCTURE_QUERY,
        Language::Swift | Language::Scala => JAVA_STRUCTURE_QUERY,
    }
}

/// Get the calls query S-expression for a language.
pub fn calls_query_for(lang: Language) -> &'static str {
    match lang {
        Language::TypeScript | Language::JavaScript => TS_JS_CALLS_QUERY,
        Language::Python => PYTHON_CALLS_QUERY,
        Language::Java => JAVA_CALLS_QUERY,
        Language::CSharp => CSHARP_CALLS_QUERY,
        Language::Go => GO_CALLS_QUERY,
        Language::Rust => RUST_CALLS_QUERY,
        Language::Ruby => RUBY_CALLS_QUERY,
        Language::Php => PHP_CALLS_QUERY,
        Language::Kotlin => KOTLIN_CALLS_QUERY,
        Language::Cpp | Language::C => CSHARP_CALLS_QUERY,
        Language::Swift | Language::Scala => JAVA_CALLS_QUERY,
    }
}

// ---- TypeScript / JavaScript ----

const TS_JS_STRUCTURE_QUERY: &str = r#"
(function_declaration
  name: (identifier) @function.name) @function.def

(arrow_function) @function.arrow

(method_definition
  name: (property_identifier) @method.name) @method.def

(class_declaration
  name: (type_identifier) @class.name) @class.def

(import_statement) @import

(export_statement) @export

(interface_declaration
  name: (type_identifier) @interface.name) @interface.def

(type_alias_declaration
  name: (type_identifier) @type_alias.name) @type_alias.def
"#;

const TS_JS_CALLS_QUERY: &str = r#"
(call_expression
  function: (identifier) @call.name) @call

(call_expression
  function: (member_expression
    object: (identifier) @call.receiver
    property: (property_identifier) @call.method)) @call.member

(await_expression
  (call_expression) @call.await)

(decorator
  (identifier) @decorator.name) @decorator

(decorator
  (call_expression
    function: (identifier) @decorator.call_name)) @decorator.call

(string) @string_literal
(template_string) @template_literal
(number) @numeric_literal

(try_statement) @try_catch
(throw_statement) @throw
"#;

// ---- Python ----

const PYTHON_STRUCTURE_QUERY: &str = r#"
(function_definition
  name: (identifier) @function.name) @function.def

(class_definition
  name: (identifier) @class.name) @class.def

(import_statement) @import
(import_from_statement) @import_from

(decorated_definition) @decorated
"#;

const PYTHON_CALLS_QUERY: &str = r#"
(call
  function: (identifier) @call.name) @call

(call
  function: (attribute
    object: (identifier) @call.receiver
    attribute: (identifier) @call.method)) @call.member

(decorator
  (identifier) @decorator.name) @decorator

(string) @string_literal
(integer) @numeric_literal
(float) @numeric_literal

(try_statement) @try_except
(raise_statement) @raise
"#;

// ---- Java ----

const JAVA_STRUCTURE_QUERY: &str = r#"
(method_declaration
  name: (identifier) @function.name) @function.def

(constructor_declaration
  name: (identifier) @constructor.name) @constructor.def

(class_declaration
  name: (identifier) @class.name) @class.def

(interface_declaration
  name: (identifier) @interface.name) @interface.def

(import_declaration) @import

(package_declaration) @package
"#;

const JAVA_CALLS_QUERY: &str = r#"
(method_invocation
  name: (identifier) @call.name) @call

(method_invocation
  object: (identifier) @call.receiver
  name: (identifier) @call.method) @call.member

(marker_annotation
  name: (identifier) @decorator.name) @decorator

(string_literal) @string_literal
(decimal_integer_literal) @numeric_literal
(decimal_floating_point_literal) @numeric_literal

(try_statement) @try_catch
(throw_statement) @throw
"#;

// ---- C# ----

const CSHARP_STRUCTURE_QUERY: &str = r#"
(method_declaration
  name: (identifier) @function.name) @function.def

(constructor_declaration
  name: (identifier) @constructor.name) @constructor.def

(class_declaration
  name: (identifier) @class.name) @class.def

(interface_declaration
  name: (identifier) @interface.name) @interface.def

(using_directive) @import

(namespace_declaration) @namespace
"#;

const CSHARP_CALLS_QUERY: &str = r#"
(invocation_expression
  function: (identifier) @call.name) @call

(invocation_expression
  function: (member_access_expression
    name: (identifier) @call.method)) @call.member

(attribute
  name: (identifier) @decorator.name) @decorator

(string_literal) @string_literal
(integer_literal) @numeric_literal
(real_literal) @numeric_literal

(try_statement) @try_catch
(throw_statement) @throw
"#;

// ---- Go ----

const GO_STRUCTURE_QUERY: &str = r#"
(function_declaration
  name: (identifier) @function.name) @function.def

(method_declaration
  name: (field_identifier) @method.name) @method.def

(type_declaration
  (type_spec
    name: (type_identifier) @type.name)) @type.def

(import_declaration) @import

(package_clause) @package
"#;

const GO_CALLS_QUERY: &str = r#"
(call_expression
  function: (identifier) @call.name) @call

(call_expression
  function: (selector_expression
    operand: (identifier) @call.receiver
    field: (field_identifier) @call.method)) @call.member

(interpreted_string_literal) @string_literal
(raw_string_literal) @string_literal
(int_literal) @numeric_literal
(float_literal) @numeric_literal

(defer_statement) @defer
"#;

// ---- Rust ----

const RUST_STRUCTURE_QUERY: &str = r#"
(function_item
  name: (identifier) @function.name) @function.def

(impl_item
  type: (type_identifier) @impl.name) @impl.def

(struct_item
  name: (type_identifier) @struct.name) @struct.def

(enum_item
  name: (type_identifier) @enum.name) @enum.def

(trait_item
  name: (type_identifier) @trait.name) @trait.def

(use_declaration) @import

(mod_item) @module
"#;

const RUST_CALLS_QUERY: &str = r#"
(call_expression
  function: (identifier) @call.name) @call

(call_expression
  function: (field_expression
    field: (field_identifier) @call.method)) @call.member

(macro_invocation
  macro: (identifier) @macro.name) @macro_call

(string_literal) @string_literal
(integer_literal) @numeric_literal
(float_literal) @numeric_literal

(attribute_item) @attribute
"#;

// ---- Ruby ----

const RUBY_STRUCTURE_QUERY: &str = r#"
(method
  name: (identifier) @function.name) @function.def

(singleton_method
  name: (identifier) @function.name) @function.static

(class
  name: (constant) @class.name) @class.def

(module
  name: (constant) @module.name) @module.def
"#;

const RUBY_CALLS_QUERY: &str = r#"
(call
  method: (identifier) @call.name) @call

(call
  receiver: (identifier) @call.receiver
  method: (identifier) @call.method) @call.member

(string) @string_literal
(integer) @numeric_literal
(float) @numeric_literal

(begin) @begin_rescue
(raise) @raise
"#;

// ---- PHP ----

const PHP_STRUCTURE_QUERY: &str = r#"
(function_definition
  name: (name) @function.name) @function.def

(method_declaration
  name: (name) @method.name) @method.def

(class_declaration
  name: (name) @class.name) @class.def

(interface_declaration
  name: (name) @interface.name) @interface.def

(namespace_definition) @namespace
"#;

const PHP_CALLS_QUERY: &str = r#"
(function_call_expression
  function: (name) @call.name) @call

(member_call_expression
  name: (name) @call.method) @call.member

(attribute) @decorator

(string) @string_literal
(integer) @numeric_literal
(float) @numeric_literal

(try_statement) @try_catch
(throw_expression) @throw
"#;

// ---- Kotlin ----

const KOTLIN_STRUCTURE_QUERY: &str = r#"
(function_declaration
  (simple_identifier) @function.name) @function.def

(class_declaration
  (type_identifier) @class.name) @class.def

(object_declaration
  (type_identifier) @object.name) @object.def

(import_header) @import

(package_header) @package
"#;

const KOTLIN_CALLS_QUERY: &str = r#"
(call_expression
  (simple_identifier) @call.name) @call

(call_expression
  (navigation_expression
    (simple_identifier) @call.receiver
    (navigation_suffix
      (simple_identifier) @call.method))) @call.member

(annotation
  (user_type
    (type_identifier) @decorator.name)) @decorator

(string_literal) @string_literal
(integer_literal) @numeric_literal
(real_literal) @numeric_literal

(try_expression) @try_catch
(throw) @throw
"#;
