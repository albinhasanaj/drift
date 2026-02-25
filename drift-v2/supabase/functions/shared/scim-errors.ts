import { SCIM_SCHEMAS } from "./scim-types.ts";

/** SCIM error types per RFC 7644 §3.12 */
export type ScimErrorType =
  | "invalidFilter"
  | "tooMany"
  | "uniqueness"
  | "mutability"
  | "invalidSyntax"
  | "invalidPath"
  | "noTarget"
  | "invalidValue"
  | "invalidVers"
  | "sensitive";

/**
 * SCIM-compliant error class.
 * Produces responses conforming to RFC 7644 §3.12.
 * Content-Type: application/scim+json
 */
export class ScimError extends Error {
  public readonly status: number;
  public readonly scimType?: ScimErrorType;

  constructor(status: number, detail: string, scimType?: ScimErrorType) {
    super(detail);
    this.name = "ScimError";
    this.status = status;
    this.scimType = scimType;
  }

  /** Convert to a SCIM-compliant JSON Response */
  toResponse(): Response {
    const body: Record<string, unknown> = {
      schemas: [SCIM_SCHEMAS.ERROR],
      status: String(this.status),
      detail: this.message,
    };
    if (this.scimType) {
      body.scimType = this.scimType;
    }
    return new Response(JSON.stringify(body), {
      status: this.status,
      headers: { "Content-Type": "application/scim+json" },
    });
  }
}

// ── Factory helpers ──

export function invalidFilter(detail: string): ScimError {
  return new ScimError(400, detail, "invalidFilter");
}

export function invalidSyntax(detail: string): ScimError {
  return new ScimError(400, detail, "invalidSyntax");
}

export function invalidValue(detail: string): ScimError {
  return new ScimError(400, detail, "invalidValue");
}

export function invalidPath(detail: string): ScimError {
  return new ScimError(400, detail, "invalidPath");
}

export function noTarget(detail: string): ScimError {
  return new ScimError(400, detail, "noTarget");
}

export function uniquenessConflict(detail: string): ScimError {
  return new ScimError(409, detail, "uniqueness");
}

export function unauthorized(detail: string = "Authentication required"): ScimError {
  return new ScimError(401, detail);
}

export function forbidden(detail: string = "Insufficient permissions"): ScimError {
  return new ScimError(403, detail);
}

export function notFound(detail: string = "Resource not found"): ScimError {
  return new ScimError(404, detail);
}

export function internalError(detail: string = "Internal server error"): ScimError {
  return new ScimError(500, detail);
}

/**
 * Wrap a handler to catch ScimError and return proper SCIM error responses.
 * Non-ScimError exceptions produce a generic 500 with no internal details.
 */
export function withScimErrorHandler(
  handler: (req: Request) => Promise<Response>,
): (req: Request) => Promise<Response> {
  return async (req: Request) => {
    try {
      return await handler(req);
    } catch (err) {
      if (err instanceof ScimError) {
        return err.toResponse();
      }
      // Never expose internal errors to SCIM clients
      console.error("Unhandled SCIM error:", err);
      return internalError().toResponse();
    }
  };
}

/** Create a successful SCIM JSON response */
export function scimResponse(body: unknown, status: number = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/scim+json" },
  });
}

/** Create a 204 No Content response */
export function noContentResponse(): Response {
  return new Response(null, { status: 204 });
}

/** Create a 201 Created response with Location header */
export function createdResponse(body: unknown, location: string): Response {
  return new Response(JSON.stringify(body), {
    status: 201,
    headers: {
      "Content-Type": "application/scim+json",
      Location: location,
    },
  });
}
