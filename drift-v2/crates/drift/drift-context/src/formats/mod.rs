//! Output formats — XML, YAML, Markdown.

pub mod xml;
pub mod yaml;
pub mod markdown;

pub use xml::XmlFormatter;
pub use yaml::YamlFormatter;
pub use markdown::MarkdownFormatter;
