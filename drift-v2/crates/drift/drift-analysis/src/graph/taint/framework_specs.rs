//! Framework-specific taint specifications.
//!
//! Provides pre-configured source/sink/sanitizer patterns for popular frameworks.

use super::registry::{SanitizerPattern, SinkPattern, SourcePattern, TaintRegistry};
use super::types::{SanitizerType, SinkType, SourceType};

/// Supported frameworks for taint specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintFramework {
    Express,
    Django,
    Flask,
    Spring,
    AspNet,
    Rails,
    Laravel,
    Fastify,
    Koa,
    NestJs,
    Gin,
    Actix,
}

impl TaintFramework {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Express => "express",
            Self::Django => "django",
            Self::Flask => "flask",
            Self::Spring => "spring",
            Self::AspNet => "aspnet",
            Self::Rails => "rails",
            Self::Laravel => "laravel",
            Self::Fastify => "fastify",
            Self::Koa => "koa",
            Self::NestJs => "nestjs",
            Self::Gin => "gin",
            Self::Actix => "actix",
        }
    }

    /// All supported frameworks.
    pub fn all() -> &'static [TaintFramework] {
        &[
            Self::Express, Self::Django, Self::Flask, Self::Spring,
            Self::AspNet, Self::Rails, Self::Laravel, Self::Fastify,
            Self::Koa, Self::NestJs, Self::Gin, Self::Actix,
        ]
    }
}

/// Apply framework-specific patterns to a registry.
pub fn apply_framework_specs(registry: &mut TaintRegistry, framework: TaintFramework) {
    match framework {
        TaintFramework::Express => apply_express(registry),
        TaintFramework::Django => apply_django(registry),
        TaintFramework::Flask => apply_flask(registry),
        TaintFramework::Spring => apply_spring(registry),
        TaintFramework::AspNet => apply_aspnet(registry),
        TaintFramework::Rails => apply_rails(registry),
        TaintFramework::Laravel => apply_laravel(registry),
        TaintFramework::Fastify => apply_fastify(registry),
        TaintFramework::Koa => apply_koa(registry),
        TaintFramework::NestJs => apply_nestjs(registry),
        TaintFramework::Gin => apply_gin(registry),
        TaintFramework::Actix => apply_actix(registry),
    }
}

fn apply_express(registry: &mut TaintRegistry) {
    let sources = ["req.query", "req.body", "req.params", "req.headers", "req.cookies", "req.ip"];
    for s in &sources {
        registry.add_source(SourcePattern {
            pattern: s.to_string(),
            source_type: SourceType::UserInput,
            framework: Some("express".to_string()),
        });
    }
    registry.add_sink(SinkPattern {
        pattern: "res.send".to_string(),
        sink_type: SinkType::HtmlOutput,
        required_sanitizers: vec![SanitizerType::HtmlEscape],
        framework: Some("express".to_string()),
    });
    registry.add_sink(SinkPattern {
        pattern: "res.redirect".to_string(),
        sink_type: SinkType::HttpRedirect,
        required_sanitizers: vec![SanitizerType::UrlEncode],
        framework: Some("express".to_string()),
    });
}

fn apply_django(registry: &mut TaintRegistry) {
    let sources = ["request.GET", "request.POST", "request.data", "request.FILES", "request.META"];
    for s in &sources {
        registry.add_source(SourcePattern {
            pattern: s.to_string(),
            source_type: SourceType::UserInput,
            framework: Some("django".to_string()),
        });
    }
    registry.add_sink(SinkPattern {
        pattern: "cursor.execute".to_string(),
        sink_type: SinkType::SqlQuery,
        required_sanitizers: vec![SanitizerType::SqlParameterize],
        framework: Some("django".to_string()),
    });
    registry.add_sanitizer(SanitizerPattern {
        pattern: "mark_safe".to_string(),
        sanitizer_type: SanitizerType::HtmlEscape,
        protects_against: vec![SinkType::HtmlOutput],
        framework: Some("django".to_string()),
    });
}

fn apply_flask(registry: &mut TaintRegistry) {
    let sources = ["request.args", "request.form", "request.json", "request.data", "request.files"];
    for s in &sources {
        registry.add_source(SourcePattern {
            pattern: s.to_string(),
            source_type: SourceType::UserInput,
            framework: Some("flask".to_string()),
        });
    }
    registry.add_sanitizer(SanitizerPattern {
        pattern: "Markup.escape".to_string(),
        sanitizer_type: SanitizerType::HtmlEscape,
        protects_against: vec![SinkType::HtmlOutput],
        framework: Some("flask".to_string()),
    });
}

fn apply_spring(registry: &mut TaintRegistry) {
    let sources = ["@RequestParam", "@RequestBody", "@PathVariable", "HttpServletRequest"];
    for s in &sources {
        registry.add_source(SourcePattern {
            pattern: s.to_string(),
            source_type: SourceType::UserInput,
            framework: Some("spring".to_string()),
        });
    }
    registry.add_sink(SinkPattern {
        pattern: "jdbcTemplate.query".to_string(),
        sink_type: SinkType::SqlQuery,
        required_sanitizers: vec![SanitizerType::SqlParameterize],
        framework: Some("spring".to_string()),
    });
}

fn apply_aspnet(registry: &mut TaintRegistry) {
    let sources = ["Request.Query", "Request.Form", "Request.Body", "Request.Headers"];
    for s in &sources {
        registry.add_source(SourcePattern {
            pattern: s.to_string(),
            source_type: SourceType::UserInput,
            framework: Some("aspnet".to_string()),
        });
    }
    registry.add_sanitizer(SanitizerPattern {
        pattern: "HtmlEncoder.Encode".to_string(),
        sanitizer_type: SanitizerType::HtmlEscape,
        protects_against: vec![SinkType::HtmlOutput],
        framework: Some("aspnet".to_string()),
    });
}

fn apply_rails(registry: &mut TaintRegistry) {
    let sources = ["params", "request.params", "request.body"];
    for s in &sources {
        registry.add_source(SourcePattern {
            pattern: s.to_string(),
            source_type: SourceType::UserInput,
            framework: Some("rails".to_string()),
        });
    }
    registry.add_sanitizer(SanitizerPattern {
        pattern: "sanitize".to_string(),
        sanitizer_type: SanitizerType::HtmlEscape,
        protects_against: vec![SinkType::HtmlOutput],
        framework: Some("rails".to_string()),
    });
    registry.add_sanitizer(SanitizerPattern {
        pattern: "h".to_string(),
        sanitizer_type: SanitizerType::HtmlEscape,
        protects_against: vec![SinkType::HtmlOutput],
        framework: Some("rails".to_string()),
    });
}

fn apply_laravel(registry: &mut TaintRegistry) {
    let sources = ["$request->input", "$request->query", "$request->post", "$request->all"];
    for s in &sources {
        registry.add_source(SourcePattern {
            pattern: s.to_string(),
            source_type: SourceType::UserInput,
            framework: Some("laravel".to_string()),
        });
    }
    registry.add_sanitizer(SanitizerPattern {
        pattern: "e(".to_string(),
        sanitizer_type: SanitizerType::HtmlEscape,
        protects_against: vec![SinkType::HtmlOutput],
        framework: Some("laravel".to_string()),
    });
}

fn apply_fastify(registry: &mut TaintRegistry) {
    let sources = ["request.query", "request.body", "request.params"];
    for s in &sources {
        registry.add_source(SourcePattern {
            pattern: s.to_string(),
            source_type: SourceType::UserInput,
            framework: Some("fastify".to_string()),
        });
    }
}

fn apply_koa(registry: &mut TaintRegistry) {
    let sources = ["ctx.query", "ctx.request.body", "ctx.params"];
    for s in &sources {
        registry.add_source(SourcePattern {
            pattern: s.to_string(),
            source_type: SourceType::UserInput,
            framework: Some("koa".to_string()),
        });
    }
}

fn apply_nestjs(registry: &mut TaintRegistry) {
    let sources = ["@Body", "@Query", "@Param", "@Headers"];
    for s in &sources {
        registry.add_source(SourcePattern {
            pattern: s.to_string(),
            source_type: SourceType::UserInput,
            framework: Some("nestjs".to_string()),
        });
    }
}

fn apply_gin(registry: &mut TaintRegistry) {
    let sources = ["c.Query", "c.PostForm", "c.Param", "c.GetHeader"];
    for s in &sources {
        registry.add_source(SourcePattern {
            pattern: s.to_string(),
            source_type: SourceType::UserInput,
            framework: Some("gin".to_string()),
        });
    }
}

fn apply_actix(registry: &mut TaintRegistry) {
    let sources = ["web::Query", "web::Json", "web::Path", "HttpRequest"];
    for s in &sources {
        registry.add_source(SourcePattern {
            pattern: s.to_string(),
            source_type: SourceType::UserInput,
            framework: Some("actix".to_string()),
        });
    }
}
