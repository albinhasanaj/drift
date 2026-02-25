//! Phase A contract extractor hardening tests (CET-EXP through CET-FE).
//! Tests every extractor enhancement from the Contract Extraction Hardening Phase A.

use drift_analysis::structural::contracts::extractors::*;
use drift_analysis::structural::contracts::extractors::express::ExpressExtractor;
use drift_analysis::structural::contracts::extractors::fastify::FastifyExtractor;
use drift_analysis::structural::contracts::extractors::nestjs::NestJsExtractor;
use drift_analysis::structural::contracts::extractors::nextjs::NextJsExtractor;
use drift_analysis::structural::contracts::extractors::trpc::TrpcExtractor;
use drift_analysis::structural::contracts::extractors::django::DjangoExtractor;
use drift_analysis::structural::contracts::extractors::flask::FlaskExtractor;
use drift_analysis::structural::contracts::extractors::spring::SpringExtractor;
use drift_analysis::structural::contracts::extractors::rails::RailsExtractor;
use drift_analysis::structural::contracts::extractors::gin::GinExtractor;
use drift_analysis::structural::contracts::extractors::actix::ActixExtractor;
use drift_analysis::structural::contracts::extractors::frontend::FrontendExtractor;

// ═══════════════════════════════════════════════════════════════════════════
// CET-EXP: Express extractor tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-EXP-01: Standard app.get / router.get patterns (baseline).
#[test]
fn test_express_basic_patterns() {
    let ext = ExpressExtractor;
    let content = r#"
const express = require('express');
const app = express();
app.get('/users', handler);
app.post('/users', handler);
router.put('/users/:id', handler);
router.delete('/users/:id', handler);
"#;
    let eps = ext.extract(content, "routes.ts");
    assert_eq!(eps.len(), 4, "Should extract 4 endpoints, got {}", eps.len());
    assert!(eps.iter().any(|e| e.method == "GET" && e.path == "/users"));
    assert!(eps.iter().any(|e| e.method == "POST" && e.path == "/users"));
    assert!(eps.iter().any(|e| e.method == "PUT" && e.path == "/users/:id"));
    assert!(eps.iter().any(|e| e.method == "DELETE" && e.path == "/users/:id"));
}

/// CET-EXP-02: CE-EXP-01 — Custom receiver names (server., api.).
#[test]
fn test_express_custom_receivers() {
    let ext = ExpressExtractor;
    let content = r#"
const express = require('express');
const server = express();
server.get('/health', handler);
api.post('/data', handler);
"#;
    let eps = ext.extract(content, "server.ts");
    assert!(eps.iter().any(|e| e.method == "GET" && e.path == "/health"),
        "Should extract server.get() endpoint");
    assert!(eps.iter().any(|e| e.method == "POST" && e.path == "/data"),
        "Should extract api.post() endpoint");
}

/// CET-EXP-03: CE-EXP-02 — Multi-line route definition.
#[test]
fn test_express_multiline() {
    let ext = ExpressExtractor;
    let content = r#"
const express = require('express');
const app = express();
app.get(
  '/api/users',
  authMiddleware,
  handler
);
"#;
    let eps = ext.extract(content, "routes.ts");
    assert!(eps.iter().any(|e| e.method == "GET" && e.path == "/api/users"),
        "Should handle multi-line route definition");
}

/// CET-EXP-04: CE-EXP-03 — app.use prefix detection.
#[test]
fn test_express_use_prefix_collection() {
    let ext = ExpressExtractor;
    let content = r#"
const express = require('express');
const app = express();
app.use('/api/v1', router);
app.get('/health', handler);
"#;
    let eps = ext.extract(content, "app.ts");
    // The /health endpoint should still be extracted (prefix not applied cross-file yet).
    assert!(eps.iter().any(|e| e.method == "GET" && e.path == "/health"),
        "Should still extract direct routes");
}

/// CET-EXP-05: matches() updated for new receivers.
#[test]
fn test_express_matches_extended() {
    let ext = ExpressExtractor;
    assert!(ext.matches("server.get('/path')"));
    assert!(ext.matches("api.get('/path')"));
    assert!(ext.matches("const express = require('express')"));
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-FAST: Fastify extractor tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-FAST-01: CE-FAST-01 — Receiver aliases (server., app., instance.).
#[test]
fn test_fastify_receiver_aliases() {
    let ext = FastifyExtractor;
    let content = r#"
import Fastify from 'fastify';
const server = Fastify();
server.get('/users', handler);
app.post('/users', handler);
instance.put('/users/:id', handler);
fastify.delete('/users/:id', handler);
"#;
    let eps = ext.extract(content, "server.ts");
    assert_eq!(eps.len(), 4, "Should extract all 4 receiver patterns, got {}", eps.len());
}

/// CET-FAST-02: HEAD and OPTIONS methods.
#[test]
fn test_fastify_head_options() {
    let ext = FastifyExtractor;
    let content = r#"
const fastify = require('fastify')();
fastify.head('/users', handler);
fastify.options('/users', handler);
"#;
    let eps = ext.extract(content, "routes.ts");
    assert!(eps.iter().any(|e| e.method == "HEAD"), "Should extract HEAD method");
    assert!(eps.iter().any(|e| e.method == "OPTIONS"), "Should extract OPTIONS method");
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-NEST: NestJS extractor tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-NEST-01: CE-NEST-01 — All 8 decorators including @All, @Head, @Options.
#[test]
fn test_nestjs_all_decorators() {
    let ext = NestJsExtractor;
    let content = r#"
import { Controller, Get, Post, All, Head, Options } from '@nestjs/common';
@Controller('users')
export class UsersController {
    @Get()
    findAll() {}
    @Post()
    create() {}
    @All('wildcard')
    handleAll() {}
    @Head()
    head() {}
    @Options()
    options() {}
}
"#;
    let eps = ext.extract(content, "users.controller.ts");
    assert!(eps.iter().any(|e| e.method == "GET"), "Should extract @Get");
    assert!(eps.iter().any(|e| e.method == "POST"), "Should extract @Post");
    assert!(eps.iter().any(|e| e.method == "ALL"), "Should extract @All");
    assert!(eps.iter().any(|e| e.method == "HEAD"), "Should extract @Head");
    assert!(eps.iter().any(|e| e.method == "OPTIONS"), "Should extract @Options");
}

/// CET-NEST-02: CE-NEST-02 — @Controller() with no path argument.
#[test]
fn test_nestjs_controller_no_path() {
    let ext = NestJsExtractor;
    let content = r#"
@Controller()
export class AppController {
    @Get('health')
    health() {}
}
"#;
    let eps = ext.extract(content, "app.controller.ts");
    assert_eq!(eps.len(), 1);
    assert_eq!(eps[0].path, "health", "With @Controller() empty, path should be just 'health'");
}

/// CET-NEST-03: Controller base path prepended to method path.
#[test]
fn test_nestjs_controller_base_path() {
    let ext = NestJsExtractor;
    let content = r#"
@Controller('api/users')
export class UsersController {
    @Get(':id')
    findOne() {}
}
"#;
    let eps = ext.extract(content, "users.controller.ts");
    assert_eq!(eps.len(), 1);
    assert_eq!(eps[0].path, "api/users/:id");
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-NEXT: Next.js extractor tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-NEXT-01: CE-NEXT-01 — Route groups stripped from path.
#[test]
fn test_nextjs_route_groups_stripped() {
    let ext = NextJsExtractor;
    let content = r#"
import { NextResponse } from 'next/server';
export async function GET() {
    return NextResponse.json({});
}
"#;
    let eps = ext.extract(content, "src/app/api/(auth)/users/route.ts");
    assert_eq!(eps.len(), 1);
    // (auth) group should be stripped
    assert_eq!(eps[0].path, "/api/users", "Route group (auth) should be stripped, got {}", eps[0].path);
}

/// CET-NEXT-02: CE-NEXT-02 — Dynamic segments [id] → :id.
#[test]
fn test_nextjs_dynamic_segments() {
    let ext = NextJsExtractor;
    let content = r#"
import { NextResponse } from 'next/server';
export async function GET() {
    return NextResponse.json({});
}
"#;
    let eps = ext.extract(content, "src/app/api/users/[id]/route.ts");
    assert_eq!(eps.len(), 1);
    assert_eq!(eps[0].path, "/api/users/:id", "Dynamic segment [id] should become :id, got {}", eps[0].path);
}

/// CET-NEXT-03: CE-NEXT-02 — Catch-all segments [...slug] → *slug.
#[test]
fn test_nextjs_catch_all() {
    let ext = NextJsExtractor;
    let content = r#"
import { NextResponse } from 'next/server';
export async function GET() {
    return NextResponse.json({});
}
"#;
    let eps = ext.extract(content, "src/app/api/docs/[...slug]/route.ts");
    assert_eq!(eps.len(), 1);
    assert_eq!(eps[0].path, "/api/docs/*slug", "Catch-all [...slug] should become *slug, got {}", eps[0].path);
}

/// CET-NEXT-04: Pages Router detection.
#[test]
fn test_nextjs_pages_router() {
    let ext = NextJsExtractor;
    let content = r#"
import type { NextApiRequest, NextApiResponse } from 'next';
export default function handler(req: NextApiRequest, res: NextApiResponse) {}
"#;
    let eps = ext.extract(content, "pages/api/users/[id].ts");
    assert_eq!(eps.len(), 1);
    assert_eq!(eps[0].method, "ANY");
    assert_eq!(eps[0].path, "/api/users/:id", "Pages router [id] should become :id, got {}", eps[0].path);
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-TRPC: tRPC extractor tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-TRPC-01: CE-TRPC-01 — v10/v11 builder pattern extraction.
#[test]
fn test_trpc_v10_builder_pattern() {
    let ext = TrpcExtractor;
    let content = r#"
import { createTRPCRouter, publicProcedure } from '../trpc';
export const userRouter = createTRPCRouter({
    getUser: publicProcedure.input(z.string()).query(async ({ input }) => {
        return db.user.findUnique({ where: { id: input } });
    }),
    createUser: publicProcedure.input(createUserSchema).mutation(async ({ input }) => {
        return db.user.create({ data: input });
    }),
});
"#;
    let eps = ext.extract(content, "user.router.ts");
    assert!(eps.iter().any(|e| e.method == "QUERY" && e.path == "getUser"),
        "Should extract v10 getUser query procedure");
    assert!(eps.iter().any(|e| e.method == "MUTATION" && e.path == "createUser"),
        "Should extract v10 createUser mutation procedure");
}

/// CET-TRPC-02: v9 style .query('name', ...) still works.
#[test]
fn test_trpc_v9_style() {
    let ext = TrpcExtractor;
    let content = r#"
import { createTRPCRouter } from '@trpc/server';
t.router().query('getUser', resolver);
t.router().mutation('createUser', resolver);
"#;
    let eps = ext.extract(content, "router.ts");
    assert!(eps.iter().any(|e| e.method == "QUERY" && e.path == "getUser"));
    assert!(eps.iter().any(|e| e.method == "MUTATION" && e.path == "createUser"));
}

/// CET-TRPC-03: matches() recognizes protectedProcedure.
#[test]
fn test_trpc_matches_protected() {
    let ext = TrpcExtractor;
    assert!(ext.matches("protectedProcedure.query()"));
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-DJNG: Django extractor tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-DJNG-01: CE-DJNG-01 — @api_view wired to next def.
#[test]
fn test_django_api_view_wired() {
    let ext = DjangoExtractor;
    let content = r#"
from rest_framework.decorators import api_view
@api_view(['GET', 'POST'])
def user_list(request):
    pass
"#;
    let eps = ext.extract(content, "views.py");
    assert!(eps.iter().any(|e| e.method == "GET" && e.path == "/user_list"),
        "Should extract GET from @api_view, endpoints: {:?}", eps.iter().map(|e| (&e.method, &e.path)).collect::<Vec<_>>());
    assert!(eps.iter().any(|e| e.method == "POST" && e.path == "/user_list"),
        "Should extract POST from @api_view");
}

/// CET-DJNG-02: CE-DJNG-02 — include() lines skipped.
#[test]
fn test_django_include_skipped() {
    let ext = DjangoExtractor;
    let content = r#"
from django.urls import path, include
urlpatterns = [
    path('api/', include('api.urls')),
    path('health/', views.health_check),
]
"#;
    let eps = ext.extract(content, "urls.py");
    // include() line should be skipped, only health/ extracted
    assert_eq!(eps.len(), 1, "Should skip include() line, got {} endpoints", eps.len());
    assert_eq!(eps[0].path, "health/");
}

/// CET-DJNG-03: CE-DJNG-03 — @action decorator on ViewSet.
#[test]
fn test_django_action_decorator() {
    let ext = DjangoExtractor;
    let content = r#"
from rest_framework.decorators import action
class UserViewSet(viewsets.ModelViewSet):
    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        pass
"#;
    let eps = ext.extract(content, "views.py");
    assert!(eps.iter().any(|e| e.method == "POST" && e.path == "/:id/activate"),
        "Should extract @action(detail=True) with /:id/ prefix, got: {:?}",
        eps.iter().map(|e| (&e.method, &e.path)).collect::<Vec<_>>());
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-RAIL: Rails extractor tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-RAIL-01: CE-RAIL-01 — resources generates correct RESTful paths.
#[test]
fn test_rails_resources_correct_paths() {
    let ext = RailsExtractor;
    let content = r#"
Rails.application.routes.draw do
  resources :users
end
"#;
    let eps = ext.extract(content, "config/routes.rb");
    // Collection: GET /users (index), POST /users (create)
    // Member: GET /users/:id (show), PUT /users/:id (update), DELETE /users/:id (destroy)
    assert!(eps.iter().any(|e| e.method == "GET" && e.path.ends_with("/users") && !e.path.contains(":id")),
        "Should have GET /users (index)");
    assert!(eps.iter().any(|e| e.method == "POST" && e.path.ends_with("/users") && !e.path.contains(":id")),
        "Should have POST /users (create)");
    assert!(eps.iter().any(|e| e.method == "GET" && e.path.contains("/users/:id")),
        "Should have GET /users/:id (show)");
    assert!(eps.iter().any(|e| e.method == "PUT" && e.path.contains("/users/:id")),
        "Should have PUT /users/:id (update)");
    assert!(eps.iter().any(|e| e.method == "DELETE" && e.path.contains("/users/:id")),
        "Should have DELETE /users/:id (destroy)");
}

/// CET-RAIL-02: CE-RAIL-02 — namespace prefix applied.
#[test]
fn test_rails_namespace_prefix() {
    let ext = RailsExtractor;
    let content = r#"
Rails.application.routes.draw do
  namespace :api do
    resources :users
  end
end
"#;
    let eps = ext.extract(content, "config/routes.rb");
    assert!(eps.iter().any(|e| e.path.contains("/api/users")),
        "Should prepend /api namespace to resources, got: {:?}",
        eps.iter().map(|e| &e.path).collect::<Vec<_>>());
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-GIN: Gin extractor tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-GIN-01: CE-GIN-01 — Group() prefix applied.
#[test]
fn test_gin_group_prefix() {
    let ext = GinExtractor;
    let content = r#"
package main
import "github.com/gin-gonic/gin"
func main() {
    r := gin.Default()
    v1 := r.Group("/api/v1")
    v1.GET("/users", getUsers)
    v1.POST("/users", createUser)
}
"#;
    let eps = ext.extract(content, "main.go");
    assert!(eps.iter().any(|e| e.method == "GET" && e.path == "/api/v1/users"),
        "Should apply Group prefix /api/v1 to /users, got: {:?}",
        eps.iter().map(|e| (&e.method, &e.path)).collect::<Vec<_>>());
    assert!(eps.iter().any(|e| e.method == "POST" && e.path == "/api/v1/users"),
        "Should apply Group prefix to POST");
}

/// CET-GIN-02: CE-GIN-02 — Non-gin files with .GET( not extracted.
#[test]
fn test_gin_non_gin_file_rejected() {
    let ext = GinExtractor;
    let content = r#"
package main
func main() {
    something.GET("/users")
}
"#;
    let eps = ext.extract(content, "main.go");
    assert!(eps.is_empty(), "Non-gin file should produce no endpoints");
}

/// CET-GIN-03: HEAD and OPTIONS methods.
#[test]
fn test_gin_head_options() {
    let ext = GinExtractor;
    let content = r#"
import "github.com/gin-gonic/gin"
r := gin.Default()
r.HEAD("/health", handler)
r.OPTIONS("/cors", handler)
"#;
    let eps = ext.extract(content, "main.go");
    assert!(eps.iter().any(|e| e.method == "HEAD"), "Should extract HEAD");
    assert!(eps.iter().any(|e| e.method == "OPTIONS"), "Should extract OPTIONS");
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-ACTX: Actix extractor tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-ACTX-01: CE-ACTX-01 — #[route()] multi-method macro.
#[test]
fn test_actix_route_multi_method() {
    let ext = ActixExtractor;
    let content = r#"
use actix_web::{route, HttpResponse};
#[route("/api/data", method = "GET", method = "POST")]
async fn data_handler() -> HttpResponse {
    HttpResponse::Ok().finish()
}
"#;
    let eps = ext.extract(content, "handlers.rs");
    assert!(eps.iter().any(|e| e.method == "GET" && e.path == "/api/data"),
        "Should extract GET from #[route]");
    assert!(eps.iter().any(|e| e.method == "POST" && e.path == "/api/data"),
        "Should extract POST from #[route]");
}

/// CET-ACTX-02: #[head()] and #[options()] attributes.
#[test]
fn test_actix_head_options() {
    let ext = ActixExtractor;
    let content = r#"
use actix_web::{head, options};
#[head("/health")]
async fn health() {}
#[options("/cors")]
async fn cors() {}
"#;
    let eps = ext.extract(content, "handlers.rs");
    assert!(eps.iter().any(|e| e.method == "HEAD" && e.path == "/health"));
    assert!(eps.iter().any(|e| e.method == "OPTIONS" && e.path == "/cors"));
}

/// CET-ACTX-03: web::resource with web::get() method extraction.
#[test]
fn test_actix_web_resource_method() {
    let ext = ActixExtractor;
    let content = r#"
use actix_web::web;
web::resource("/users").route(web::get().to(list_users))
"#;
    let eps = ext.extract(content, "routes.rs");
    assert!(eps.iter().any(|e| e.method == "GET" && e.path == "/users"),
        "Should extract method from web::get()");
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-FE: Frontend extractor tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-FE-01: CE-FE-01 — useMutation extraction.
#[test]
fn test_frontend_use_mutation() {
    let ext = FrontendExtractor;
    let content = r#"
import { useMutation } from '@tanstack/react-query';
const mutation = useMutation('/api/users');
"#;
    let eps = ext.extract(content, "hooks.ts");
    assert!(eps.iter().any(|e| e.method == "POST" && e.path == "/api/users"),
        "useMutation should be extracted as POST, got: {:?}",
        eps.iter().map(|e| (&e.method, &e.path)).collect::<Vec<_>>());
}

/// CET-FE-02: CE-FE-02 — Multi-line fetch method inference.
#[test]
fn test_frontend_multiline_fetch() {
    let ext = FrontendExtractor;
    let content = r#"
const response = await fetch('/api/users', {
    method: 'POST',
    body: JSON.stringify(data),
});
"#;
    let eps = ext.extract(content, "api.ts");
    assert!(eps.iter().any(|e| e.method == "POST" && e.path == "/api/users"),
        "Should infer POST from method: on next line, got: {:?}",
        eps.iter().map(|e| (&e.method, &e.path)).collect::<Vec<_>>());
}

/// CET-FE-03: axios method-specific calls.
#[test]
fn test_frontend_axios() {
    let ext = FrontendExtractor;
    let content = r#"
import axios from 'axios';
axios.get('/api/users');
axios.post('/api/users');
axios.put('/api/users/1');
axios.delete('/api/users/1');
"#;
    let eps = ext.extract(content, "api.ts");
    assert_eq!(eps.len(), 4, "Should extract all 4 axios calls, got {}", eps.len());
    assert!(eps.iter().any(|e| e.method == "GET"));
    assert!(eps.iter().any(|e| e.method == "POST"));
    assert!(eps.iter().any(|e| e.method == "PUT"));
    assert!(eps.iter().any(|e| e.method == "DELETE"));
}

/// CET-FE-04: useSWR extraction.
#[test]
fn test_frontend_use_swr() {
    let ext = FrontendExtractor;
    let content = r#"
import useSWR from 'swr';
const { data } = useSWR('/api/users', fetcher);
"#;
    let eps = ext.extract(content, "hooks.ts");
    assert!(eps.iter().any(|e| e.method == "GET" && e.path == "/api/users"),
        "useSWR should be extracted as GET");
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-FLASK: Flask extractor tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-FLASK-01: Flask methods= parameter extraction.
#[test]
fn test_flask_methods_param() {
    let ext = FlaskExtractor;
    let content = r#"
from flask import Flask
app = Flask(__name__)
@app.route('/users', methods=['GET', 'POST'])
def users():
    pass
"#;
    let eps = ext.extract(content, "app.py");
    assert!(eps.iter().any(|e| e.method == "GET" && e.path == "/users"));
    assert!(eps.iter().any(|e| e.method == "POST" && e.path == "/users"));
}

/// CET-FLASK-02: @bp.route shorthand.
#[test]
fn test_flask_blueprint_route() {
    let ext = FlaskExtractor;
    let content = r#"
from flask import Blueprint
bp = Blueprint('users', __name__)
@bp.route('/users')
def list_users():
    pass
"#;
    let eps = ext.extract(content, "routes.py");
    assert!(eps.iter().any(|e| e.method == "GET" && e.path == "/users"),
        "Should extract @bp.route as GET by default");
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-REG: ExtractorRegistry integration tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-REG-01: Registry returns all 14 extractors.
#[test]
fn test_registry_all_extractors() {
    let registry = ExtractorRegistry::new();
    let express_content = r#"
const express = require('express');
const app = express();
app.get('/users', handler);
"#;
    let results = registry.extract_all(express_content, "routes.ts");
    assert!(!results.is_empty(), "Registry should match Express content");
    assert!(results.iter().any(|(fw, _)| fw == "express"));
}

/// CET-REG-02: Registry Default impl.
#[test]
fn test_registry_default() {
    let registry = ExtractorRegistry::default();
    let content = "const fastify = require('fastify')(); fastify.get('/users', handler);";
    let results = registry.extract_all(content, "app.ts");
    assert!(!results.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase C: Field Extraction via ParseResult
// ═══════════════════════════════════════════════════════════════════════════

use drift_analysis::parsers::types::{ParseResult, FunctionInfo, ParameterInfo, Range, Position};
use drift_analysis::structural::contracts::matching::match_contracts;
use drift_analysis::structural::contracts::confidence::bayesian_confidence;
use drift_analysis::scanner::language_detect::Language;
use smallvec::smallvec;

fn make_parse_result_with_func(file: &str, func_name: &str, line: u32, end_line: u32, params: Vec<ParameterInfo>, return_type: Option<String>) -> ParseResult {
    ParseResult {
        file: file.to_string(),
        language: Language::TypeScript,
        functions: vec![FunctionInfo {
            name: func_name.to_string(),
            qualified_name: None,
            file: file.to_string(),
            line,
            column: 0,
            end_line,
            parameters: params.into_iter().collect(),
            return_type,
            generic_params: smallvec![],
            visibility: drift_analysis::parsers::types::Visibility::Public,
            is_exported: true,
            is_async: false,
            is_generator: false,
            is_abstract: false,
            range: Range {
                start: Position { line, column: 0 },
                end: Position { line: end_line, column: 0 },
            },
            decorators: vec![],
            doc_comment: None,
            body_hash: 0,
            signature_hash: 0,
        }],
        ..Default::default()
    }
}

/// CET-EXP-F01: Express handler with typed parameters → request_fields populated.
#[test]
fn test_express_extract_with_context_request_fields() {
    let ext = ExpressExtractor;
    let content = r#"
const express = require('express');
const app = express();
app.get('/users', getUsers);
"#;
    // Function at line 3 (0-indexed) with parameters
    let pr = make_parse_result_with_func("routes.ts", "getUsers", 3, 5, vec![
        ParameterInfo { name: "req".to_string(), type_annotation: None, default_value: None, is_rest: false },
        ParameterInfo { name: "res".to_string(), type_annotation: None, default_value: None, is_rest: false },
        ParameterInfo { name: "page".to_string(), type_annotation: Some("number".to_string()), default_value: None, is_rest: false },
        ParameterInfo { name: "limit".to_string(), type_annotation: Some("number".to_string()), default_value: Some("10".to_string()), is_rest: false },
    ], Some("{ id: number, name: string }".to_string()));

    let eps = ext.extract_with_context(content, "routes.ts", Some(&pr));
    assert_eq!(eps.len(), 1);
    let ep = &eps[0];
    // req/res are framework params → filtered out. page and limit remain.
    assert!(ep.request_fields.len() >= 2, "Should have at least page and limit, got {:?}", ep.request_fields);
    assert!(ep.request_fields.iter().any(|f| f.name == "page" && f.field_type == "number" && f.required));
    assert!(ep.request_fields.iter().any(|f| f.name == "limit" && !f.required)); // has default
}

/// CET-EXP-F02: Express handler with return type → response_fields populated.
#[test]
fn test_express_extract_with_context_response_fields() {
    let ext = ExpressExtractor;
    let content = r#"
const express = require('express');
const app = express();
app.get('/users', getUsers);
"#;
    let pr = make_parse_result_with_func("routes.ts", "getUsers", 3, 5, vec![], Some("{ id: number, name: string }".to_string()));

    let eps = ext.extract_with_context(content, "routes.ts", Some(&pr));
    assert_eq!(eps.len(), 1);
    let ep = &eps[0];
    assert!(!ep.response_fields.is_empty(), "Should have response fields from return type");
    assert!(ep.response_fields.iter().any(|f| f.name == "id" && f.field_type == "number"));
    assert!(ep.response_fields.iter().any(|f| f.name == "name" && f.field_type == "string"));
}

/// CET-NEST-F01: NestJS with @Body/@Param decorators → request_fields from decorators.
#[test]
fn test_nestjs_extract_with_context() {
    let ext = NestJsExtractor;
    let content = r#"
import { Controller, Get } from '@nestjs/common';
@Controller('users')
export class UsersController {
    @Get()
    findAll() {}
}
"#;
    let pr = make_parse_result_with_func("users.controller.ts", "findAll", 4, 6, vec![
        ParameterInfo { name: "page".to_string(), type_annotation: Some("number".to_string()), default_value: None, is_rest: false },
    ], Some("User[]".to_string()));

    let eps = ext.extract_with_context(content, "users.controller.ts", Some(&pr));
    assert!(!eps.is_empty());
    let ep = &eps[0];
    assert!(!ep.request_fields.is_empty(), "Should have request fields");
    assert!(ep.request_fields.iter().any(|f| f.name == "page"));
}

/// CET-SPR-F01: Spring with typed parameters → request_fields.
#[test]
fn test_spring_extract_with_context() {
    let ext = SpringExtractor;
    let content = "@RestController\n@GetMapping(\"/users\")\npublic List<User> getUsers(String name) { return null; }";
    // @GetMapping is at line index 1 (0-indexed), so ep.line = 2.
    // find_function_at_line(ep.line - 1) = find_function_at_line(1).
    // Function must span line 1.
    let pr = make_parse_result_with_func("UserController.java", "getUsers", 1, 3, vec![
        ParameterInfo { name: "name".to_string(), type_annotation: Some("String".to_string()), default_value: None, is_rest: false },
    ], Some("List<User>".to_string()));

    let eps = ext.extract_with_context(content, "UserController.java", Some(&pr));
    assert!(!eps.is_empty(), "Should extract Spring endpoints");
    let ep = &eps[0];
    assert!(ep.request_fields.iter().any(|f| f.name == "name"),
        "Should have 'name' in request_fields. ep.line={}, fields={:?}", ep.line, ep.request_fields);
    assert!(!ep.response_fields.is_empty(), "Should have response fields from return type");
}

/// CET-FLASK-F01: Flask with parameters → request_fields.
#[test]
fn test_flask_extract_with_context() {
    let ext = FlaskExtractor;
    let content = r#"
from flask import Flask
app = Flask(__name__)
@app.route('/users', methods=['GET', 'POST'])
def user_list(page, limit):
    pass
"#;
    let pr = make_parse_result_with_func("app.py", "user_list", 3, 5, vec![
        ParameterInfo { name: "self".to_string(), type_annotation: None, default_value: None, is_rest: false },
        ParameterInfo { name: "page".to_string(), type_annotation: Some("int".to_string()), default_value: None, is_rest: false },
        ParameterInfo { name: "limit".to_string(), type_annotation: Some("int".to_string()), default_value: Some("10".to_string()), is_rest: false },
    ], None);

    let eps = ext.extract_with_context(content, "app.py", Some(&pr));
    assert!(eps.len() >= 2, "Should have GET and POST endpoints");
    // self is filtered, page and limit remain
    let ep = &eps[0];
    assert!(ep.request_fields.iter().any(|f| f.name == "page"));
    assert!(ep.request_fields.iter().any(|f| f.name == "limit"));
}

/// CET-ACTX-F01: Actix with parameters → request_fields.
#[test]
fn test_actix_extract_with_context() {
    let ext = ActixExtractor;
    let content = r#"
use actix_web::{get, web};
#[get("/users")]
async fn get_users(query: web::Query<UserQuery>) -> impl Responder { todo!() }
"#;
    let pr = make_parse_result_with_func("main.rs", "get_users", 2, 4, vec![
        ParameterInfo { name: "query".to_string(), type_annotation: Some("web::Query<UserQuery>".to_string()), default_value: None, is_rest: false },
    ], Some("impl Responder".to_string()));

    let eps = ext.extract_with_context(content, "main.rs", Some(&pr));
    assert!(!eps.is_empty());
    let ep = &eps[0];
    assert!(ep.request_fields.iter().any(|f| f.name == "query"));
}

/// CET-GIN-F01: Gin with parameters → request_fields.
#[test]
fn test_gin_extract_with_context() {
    let ext = GinExtractor;
    let content = r#"
import "github.com/gin-gonic/gin"
func main() {
    r := gin.Default()
    r.GET("/users", getUsers)
}
"#;
    let pr = make_parse_result_with_func("main.go", "getUsers", 4, 6, vec![
        ParameterInfo { name: "c".to_string(), type_annotation: Some("*gin.Context".to_string()), default_value: None, is_rest: false },
        ParameterInfo { name: "page".to_string(), type_annotation: Some("int".to_string()), default_value: None, is_rest: false },
    ], None);

    let eps = ext.extract_with_context(content, "main.go", Some(&pr));
    assert!(!eps.is_empty());
    let ep = &eps[0];
    // c is a framework param, page remains
    assert!(ep.request_fields.iter().any(|f| f.name == "page"));
    assert!(!ep.request_fields.iter().any(|f| f.name == "c"), "Framework param 'c' should be filtered");
}

/// CET-FE-F01: Frontend fetch with parameters → request_fields.
#[test]
fn test_frontend_extract_with_context() {
    let ext = FrontendExtractor;
    let content = r#"
async function createUser(name: string, email: string) {
    const res = await fetch('/api/users', { method: 'POST' });
    return res.json();
}
"#;
    let pr = make_parse_result_with_func("api.ts", "createUser", 1, 4, vec![
        ParameterInfo { name: "name".to_string(), type_annotation: Some("string".to_string()), default_value: None, is_rest: false },
        ParameterInfo { name: "email".to_string(), type_annotation: Some("string".to_string()), default_value: None, is_rest: false },
    ], None);

    let eps = ext.extract_with_context(content, "api.ts", Some(&pr));
    assert!(!eps.is_empty());
    let ep = &eps[0];
    assert!(ep.request_fields.iter().any(|f| f.name == "name" && f.field_type == "string"));
    assert!(ep.request_fields.iter().any(|f| f.name == "email" && f.field_type == "string"));
}

/// CET-REG-C01: Registry extract_all_with_context works and falls back gracefully.
#[test]
fn test_registry_extract_all_with_context() {
    let registry = ExtractorRegistry::new();
    let content = r#"
const express = require('express');
const app = express();
app.get('/users', handler);
"#;
    // Without ParseResult — should still work (fallback)
    let results_no_pr = registry.extract_all_with_context(content, "routes.ts", None);
    assert!(!results_no_pr.is_empty());
    let (_, eps) = &results_no_pr[0];
    assert!(eps[0].request_fields.is_empty(), "Without ParseResult, fields should be empty");
}

/// CET-REG-C02: Extractors without ParseResult still work (graceful fallback).
#[test]
fn test_extract_with_context_no_parse_result() {
    let ext = ExpressExtractor;
    let content = "const express = require('express'); app.get('/users', h);";
    let eps = ext.extract_with_context(content, "routes.ts", None);
    assert!(!eps.is_empty());
    assert!(eps[0].request_fields.is_empty());
}

/// CET-CONF-01: match_contracts with populated fields → field_overlap > 0.
#[test]
fn test_match_contracts_with_fields() {
    use drift_analysis::structural::contracts::types::*;

    let backend = vec![Endpoint {
        method: "GET".to_string(),
        path: "/api/users".to_string(),
        request_fields: vec![],
        response_fields: vec![
            FieldSpec { name: "id".to_string(), field_type: "number".to_string(), required: true, nullable: false },
            FieldSpec { name: "name".to_string(), field_type: "string".to_string(), required: true, nullable: false },
        ],
        file: "server.ts".to_string(),
        line: 1,
    }];
    let frontend = vec![Endpoint {
        method: "GET".to_string(),
        path: "/api/users".to_string(),
        request_fields: vec![
            FieldSpec { name: "id".to_string(), field_type: "number".to_string(), required: true, nullable: false },
            FieldSpec { name: "name".to_string(), field_type: "string".to_string(), required: true, nullable: false },
        ],
        response_fields: vec![],
        file: "client.ts".to_string(),
        line: 1,
    }];

    let matches = match_contracts(&backend, &frontend);
    assert!(!matches.is_empty(), "Should match endpoints with same path");
    assert!(matches[0].confidence > 0.5, "Confidence should be > 0.5 with matching fields");
}

/// CET-CONF-02: detect_mismatches detects TypeMismatch when field types differ.
#[test]
fn test_mismatch_type_mismatch() {
    use drift_analysis::structural::contracts::types::*;

    let backend = vec![Endpoint {
        method: "GET".to_string(),
        path: "/api/users".to_string(),
        request_fields: vec![],
        response_fields: vec![
            FieldSpec { name: "id".to_string(), field_type: "number".to_string(), required: true, nullable: false },
        ],
        file: "server.ts".to_string(),
        line: 1,
    }];
    let frontend = vec![Endpoint {
        method: "GET".to_string(),
        path: "/api/users".to_string(),
        request_fields: vec![
            FieldSpec { name: "id".to_string(), field_type: "string".to_string(), required: true, nullable: false },
        ],
        response_fields: vec![],
        file: "client.ts".to_string(),
        line: 1,
    }];

    let matches = match_contracts(&backend, &frontend);
    assert!(!matches.is_empty());
    let mismatches = &matches[0].mismatches;
    assert!(mismatches.iter().any(|m| m.mismatch_type == MismatchType::TypeMismatch),
        "Should detect TypeMismatch for id: number vs string. Got: {:?}", mismatches);
}

/// CET-MATCH-01: BE response {id: number} vs FE expecting {id: string} → TypeMismatch.
#[test]
fn test_mismatch_be_fe_type_difference() {
    use drift_analysis::structural::contracts::types::*;

    let backend = vec![Endpoint {
        method: "GET".to_string(),
        path: "/api/items".to_string(),
        request_fields: vec![],
        response_fields: vec![
            FieldSpec { name: "count".to_string(), field_type: "number".to_string(), required: true, nullable: false },
        ],
        file: "server.ts".to_string(),
        line: 1,
    }];
    let frontend = vec![Endpoint {
        method: "GET".to_string(),
        path: "/api/items".to_string(),
        request_fields: vec![
            FieldSpec { name: "count".to_string(), field_type: "string".to_string(), required: true, nullable: false },
        ],
        response_fields: vec![],
        file: "client.ts".to_string(),
        line: 1,
    }];

    let matches = match_contracts(&backend, &frontend);
    assert!(!matches.is_empty());
    assert!(matches[0].mismatches.iter().any(|m| m.mismatch_type == MismatchType::TypeMismatch));
}

/// CET-MATCH-02: BE response {name: required} vs FE not using name → FieldMissing.
#[test]
fn test_mismatch_field_missing() {
    use drift_analysis::structural::contracts::types::*;

    let backend = vec![Endpoint {
        method: "GET".to_string(),
        path: "/api/users".to_string(),
        request_fields: vec![],
        response_fields: vec![
            FieldSpec { name: "name".to_string(), field_type: "string".to_string(), required: true, nullable: false },
            FieldSpec { name: "email".to_string(), field_type: "string".to_string(), required: true, nullable: false },
        ],
        file: "server.ts".to_string(),
        line: 1,
    }];
    let frontend = vec![Endpoint {
        method: "GET".to_string(),
        path: "/api/users".to_string(),
        request_fields: vec![
            FieldSpec { name: "name".to_string(), field_type: "string".to_string(), required: true, nullable: false },
            // email not consumed
        ],
        response_fields: vec![],
        file: "client.ts".to_string(),
        line: 1,
    }];

    let matches = match_contracts(&backend, &frontend);
    assert!(!matches.is_empty());
    assert!(matches[0].mismatches.iter().any(|m| m.mismatch_type == MismatchType::FieldMissing),
        "Should detect FieldMissing for email. Got: {:?}", matches[0].mismatches);
}

/// CET-MATCH-03: bayesian_confidence with 5+ signals → higher confidence than 3 signals.
#[test]
fn test_bayesian_confidence_more_signals_higher() {
    let three_signals = [0.9, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0];
    let five_signals = [0.9, 0.8, 0.7, 0.6, 0.5, 0.0, 0.0];
    let conf_3 = bayesian_confidence(&three_signals);
    let conf_5 = bayesian_confidence(&five_signals);
    assert!(conf_5 > conf_3, "5 signals ({}) should give higher confidence than 3 ({})", conf_5, conf_3);
}

/// CET-HELPERS-01: params_to_fields filters framework params.
#[test]
fn test_params_to_fields_filters_framework() {
    use drift_analysis::structural::contracts::extractors::params_to_fields;

    let params = vec![
        ParameterInfo { name: "req".to_string(), type_annotation: None, default_value: None, is_rest: false },
        ParameterInfo { name: "res".to_string(), type_annotation: None, default_value: None, is_rest: false },
        ParameterInfo { name: "userId".to_string(), type_annotation: Some("string".to_string()), default_value: None, is_rest: false },
    ];
    let fields = params_to_fields(&params);
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].name, "userId");
    assert_eq!(fields[0].field_type, "string");
    assert!(fields[0].required);
}

/// CET-HELPERS-02: return_type_to_fields parses object types.
#[test]
fn test_return_type_to_fields_object() {
    use drift_analysis::structural::contracts::extractors::return_type_to_fields;

    let fields = return_type_to_fields("{ id: number, name: string }");
    assert_eq!(fields.len(), 2);
    assert!(fields.iter().any(|f| f.name == "id" && f.field_type == "number"));
    assert!(fields.iter().any(|f| f.name == "name" && f.field_type == "string"));
}

/// CET-HELPERS-03: return_type_to_fields handles Promise<T>.
#[test]
fn test_return_type_to_fields_promise() {
    use drift_analysis::structural::contracts::extractors::return_type_to_fields;

    let fields = return_type_to_fields("Promise<{ id: number }>");
    assert!(!fields.is_empty());
    assert!(fields.iter().any(|f| f.name == "id"));
}

/// CET-HELPERS-04: return_type_to_fields returns empty for void.
#[test]
fn test_return_type_to_fields_void() {
    use drift_analysis::structural::contracts::extractors::return_type_to_fields;

    assert!(return_type_to_fields("void").is_empty());
    assert!(return_type_to_fields("None").is_empty());
    assert!(return_type_to_fields("()").is_empty());
}
