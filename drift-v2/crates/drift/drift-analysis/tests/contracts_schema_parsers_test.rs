//! Phase B schema parser hardening tests (CET-OA, CET-GQL, CET-PB, CET-AA).

use drift_analysis::structural::contracts::schema_parsers::openapi::OpenApiParser;
use drift_analysis::structural::contracts::schema_parsers::graphql::GraphqlParser;
use drift_analysis::structural::contracts::schema_parsers::protobuf::ProtobufParser;
use drift_analysis::structural::contracts::schema_parsers::asyncapi::AsyncApiParser;
use drift_analysis::structural::contracts::schema_parsers::SchemaParser;

// ═══════════════════════════════════════════════════════════════════════════
// CET-OA: OpenAPI parser tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-OA-01: $ref resolution for response schemas.
#[test]
fn test_openapi_ref_resolution() {
    let spec = r##"{
  "openapi": "3.1.0",
  "info": { "title": "Test", "version": "1.0" },
  "paths": {
    "/users": {
      "get": {
        "responses": {
          "200": {
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/User" }
              }
            }
          }
        }
      }
    }
  },
  "components": {
    "schemas": {
      "User": {
        "type": "object",
        "required": ["id", "email"],
        "properties": {
          "id": { "type": "integer" },
          "email": { "type": "string" },
          "name": { "type": "string" }
        }
      }
    }
  }
}"##;

    let parser = OpenApiParser;
    let contracts = parser.parse(spec, "api.json");
    assert_eq!(contracts.len(), 1);
    let ep = &contracts[0].endpoints[0];
    assert!(!ep.response_fields.is_empty(),
        "$ref should be resolved to extract User fields, got {} fields", ep.response_fields.len());
    assert!(ep.response_fields.iter().any(|f| f.name == "id" && f.field_type == "integer" && f.required),
        "Should resolve id field as required integer");
    assert!(ep.response_fields.iter().any(|f| f.name == "email" && f.required),
        "email should be required");
    assert!(ep.response_fields.iter().any(|f| f.name == "name" && !f.required),
        "name should be optional");
}

/// CET-OA-02: allOf composed schema merges properties.
#[test]
fn test_openapi_allof_composition() {
    let spec = r##"{
  "openapi": "3.1.0",
  "info": { "title": "Test", "version": "1.0" },
  "paths": {
    "/users": {
      "post": {
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "allOf": [
                  { "$ref": "#/components/schemas/BaseUser" },
                  {
                    "type": "object",
                    "properties": {
                      "password": { "type": "string" }
                    },
                    "required": ["password"]
                  }
                ]
              }
            }
          }
        },
        "responses": { "201": { "description": "Created" } }
      }
    }
  },
  "components": {
    "schemas": {
      "BaseUser": {
        "type": "object",
        "required": ["email"],
        "properties": {
          "email": { "type": "string" },
          "name": { "type": "string" }
        }
      }
    }
  }
}"##;

    let parser = OpenApiParser;
    let contracts = parser.parse(spec, "api.json");
    assert_eq!(contracts.len(), 1);
    let ep = &contracts[0].endpoints[0];
    assert!(ep.request_fields.len() >= 3,
        "allOf should merge BaseUser + inline schema, got {} fields: {:?}",
        ep.request_fields.len(),
        ep.request_fields.iter().map(|f| &f.name).collect::<Vec<_>>());
    assert!(ep.request_fields.iter().any(|f| f.name == "email"));
    assert!(ep.request_fields.iter().any(|f| f.name == "password"));
    assert!(ep.request_fields.iter().any(|f| f.name == "name"));
}

/// CET-OA-03: $ref on parameters.
#[test]
fn test_openapi_ref_on_parameters() {
    let spec = r##"{
  "openapi": "3.1.0",
  "info": { "title": "Test", "version": "1.0" },
  "paths": {
    "/users/{id}": {
      "get": {
        "parameters": [
          { "$ref": "#/components/parameters/UserId" }
        ],
        "responses": { "200": { "description": "OK" } }
      }
    }
  },
  "components": {
    "parameters": {
      "UserId": {
        "name": "id",
        "in": "path",
        "required": true,
        "schema": { "type": "integer" }
      }
    }
  }
}"##;

    let parser = OpenApiParser;
    let contracts = parser.parse(spec, "api.json");
    assert_eq!(contracts.len(), 1);
    let ep = &contracts[0].endpoints[0];
    assert!(ep.request_fields.iter().any(|f| f.name == "id" && f.required && f.field_type == "integer"),
        "Should resolve $ref parameter, got: {:?}", ep.request_fields);
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-GQL: GraphQL parser tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-GQL-01: extend type Query adds fields.
#[test]
fn test_graphql_extend_type() {
    let schema = r#"
type Query {
    users: [User!]!
}

extend type Query {
    posts: [Post!]!
    comments(postId: ID!): [Comment!]!
}
"#;

    let parser = GraphqlParser;
    let contracts = parser.parse(schema, "schema.graphql");
    assert!(!contracts.is_empty(), "Should parse extended GraphQL schema");
    let total: usize = contracts.iter().map(|c| c.endpoints.len()).sum();
    assert!(total >= 3,
        "Should find users + posts + comments = 3 queries, got {}", total);
}

/// CET-GQL-02: input types are parsed.
#[test]
fn test_graphql_input_types() {
    let schema = r#"
input CreateUserInput {
    name: String!
    email: String!
    age: Int
}

type Mutation {
    createUser(input: CreateUserInput!): User!
}
"#;

    let parser = GraphqlParser;
    let contracts = parser.parse(schema, "schema.graphql");
    assert!(!contracts.is_empty());
    let mutation = contracts[0].endpoints.iter().find(|e| e.path == "createUser");
    assert!(mutation.is_some(), "Should find createUser mutation");
    let m = mutation.unwrap();
    assert!(!m.request_fields.is_empty(), "Should extract input argument");
}

/// CET-GQL-03: Subscription type fields.
#[test]
fn test_graphql_subscription() {
    let schema = r#"
type Subscription {
    messageAdded(channelId: ID!): Message!
}
"#;

    let parser = GraphqlParser;
    let contracts = parser.parse(schema, "schema.graphql");
    assert!(!contracts.is_empty());
    assert!(contracts[0].endpoints.iter().any(|e| e.method == "Subscription" && e.path == "messageAdded"));
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-PB: Protobuf parser tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-PB-01: Message field resolution.
#[test]
fn test_protobuf_message_resolution() {
    let proto = r#"
syntax = "proto3";

message GetUserRequest {
    string user_id = 1;
}

message GetUserResponse {
    string user_id = 1;
    string name = 2;
    string email = 3;
}

service UserService {
    rpc GetUser(GetUserRequest) returns (GetUserResponse);
}
"#;

    let parser = ProtobufParser;
    let contracts = parser.parse(proto, "user.proto");
    assert_eq!(contracts.len(), 1);
    let ep = &contracts[0].endpoints[0];
    assert_eq!(ep.path, "GetUser");

    // Request fields should be resolved from GetUserRequest message.
    assert!(ep.request_fields.iter().any(|f| f.name == "user_id"),
        "Should resolve GetUserRequest.user_id, got: {:?}", ep.request_fields);

    // Response fields should be resolved from GetUserResponse message.
    assert!(ep.response_fields.len() >= 3,
        "Should resolve all 3 fields from GetUserResponse, got {}", ep.response_fields.len());
    assert!(ep.response_fields.iter().any(|f| f.name == "name"));
    assert!(ep.response_fields.iter().any(|f| f.name == "email"));
}

/// CET-PB-02: Stream keyword handled.
#[test]
fn test_protobuf_streaming() {
    let proto = r#"
syntax = "proto3";

message StreamRequest {
    string query = 1;
}

message StreamResponse {
    string data = 1;
}

service StreamService {
    rpc StreamData(stream StreamRequest) returns (stream StreamResponse);
}
"#;

    let parser = ProtobufParser;
    let contracts = parser.parse(proto, "stream.proto");
    assert_eq!(contracts.len(), 1);
    let ep = &contracts[0].endpoints[0];
    assert_eq!(ep.path, "StreamData");
    // Should resolve past the `stream` keyword to the actual message.
    assert!(ep.request_fields.iter().any(|f| f.name == "query"),
        "Should resolve StreamRequest.query past `stream` keyword, got: {:?}", ep.request_fields);
    assert!(ep.response_fields.iter().any(|f| f.name == "data"),
        "Should resolve StreamResponse.data past `stream` keyword");
}

/// CET-PB-03: repeated fields parsed.
#[test]
fn test_protobuf_repeated_fields() {
    let proto = r#"
syntax = "proto3";

message ListUsersRequest {
    repeated string user_ids = 1;
    int32 limit = 2;
}

message ListUsersResponse {
    repeated string names = 1;
}

service UserService {
    rpc ListUsers(ListUsersRequest) returns (ListUsersResponse);
}
"#;

    let parser = ProtobufParser;
    let contracts = parser.parse(proto, "user.proto");
    assert_eq!(contracts.len(), 1);
    let ep = &contracts[0].endpoints[0];
    assert!(ep.request_fields.len() >= 2,
        "Should parse both repeated and scalar fields, got {}", ep.request_fields.len());
}

// ═══════════════════════════════════════════════════════════════════════════
// CET-AA: AsyncAPI parser tests
// ═══════════════════════════════════════════════════════════════════════════

/// CET-AA-01: AsyncAPI 3.0 operations key.
#[test]
fn test_asyncapi_v3_operations() {
    let spec = r##"{
  "asyncapi": "3.0.0",
  "info": { "title": "Test", "version": "1.0" },
  "channels": {
    "userSignedUp": {
      "address": "user/signedup"
    }
  },
  "operations": {
    "onUserSignedUp": {
      "action": "receive",
      "channel": { "$ref": "#/channels/userSignedUp" },
      "messages": [
        {
          "payload": {
            "type": "object",
            "required": ["userId"],
            "properties": {
              "userId": { "type": "string" },
              "email": { "type": "string" }
            }
          }
        }
      ]
    }
  }
}"##;

    let parser = AsyncApiParser;
    let contracts = parser.parse(spec, "asyncapi.json");
    assert_eq!(contracts.len(), 1);
    let ep = &contracts[0].endpoints[0];
    assert_eq!(ep.method, "RECEIVE");
    assert!(!ep.request_fields.is_empty(), "Should extract message fields from v3 operations");
    assert!(ep.request_fields.iter().any(|f| f.name == "userId" && f.required),
        "userId should be required per required array");
}

/// CET-AA-02: AsyncAPI 2.x required field parsing.
#[test]
fn test_asyncapi_v2_required_fields() {
    let spec = r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Test", "version": "1.0" },
  "channels": {
    "user/created": {
      "publish": {
        "message": {
          "payload": {
            "type": "object",
            "required": ["userId", "email"],
            "properties": {
              "userId": { "type": "string" },
              "email": { "type": "string" },
              "name": { "type": "string" }
            }
          }
        }
      }
    }
  }
}"#;

    let parser = AsyncApiParser;
    let contracts = parser.parse(spec, "asyncapi.json");
    assert_eq!(contracts.len(), 1);
    let ep = &contracts[0].endpoints[0];
    assert!(ep.request_fields.iter().any(|f| f.name == "userId" && f.required),
        "userId should be required, got: {:?}",
        ep.request_fields.iter().map(|f| (&f.name, f.required)).collect::<Vec<_>>());
    assert!(ep.request_fields.iter().any(|f| f.name == "email" && f.required));
    assert!(ep.request_fields.iter().any(|f| f.name == "name" && !f.required),
        "name should NOT be required");
}
