// SCIM 2.0 Resource Types (RFC 7643 §4.1, §4.2)

/** SCIM schema URNs */
export const SCIM_SCHEMAS = {
  USER: "urn:ietf:params:scim:schemas:core:2.0:User",
  GROUP: "urn:ietf:params:scim:schemas:core:2.0:Group",
  LIST_RESPONSE: "urn:ietf:params:scim:api:messages:2.0:ListResponse",
  PATCH_OP: "urn:ietf:params:scim:api:messages:2.0:PatchOp",
  ERROR: "urn:ietf:params:scim:api:messages:2.0:Error",
  SERVICE_PROVIDER_CONFIG:
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
} as const;

/** SCIM User Name sub-resource (RFC 7643 §4.1.1) */
export interface ScimUserName {
  givenName?: string;
  familyName?: string;
  formatted?: string;
}

/** SCIM Email sub-resource (RFC 7643 §4.1.2) */
export interface ScimEmail {
  value: string;
  type?: string;
  primary?: boolean;
}

/** SCIM Meta sub-resource (RFC 7643 §3.1) */
export interface ScimMeta {
  resourceType: string;
  created: string;
  lastModified: string;
  location: string;
}

/** SCIM User Resource (RFC 7643 §4.1) */
export interface ScimUser {
  schemas: string[];
  id: string;
  externalId?: string;
  userName: string;
  name?: ScimUserName;
  displayName?: string;
  emails?: ScimEmail[];
  active: boolean;
  meta: ScimMeta;
}

/** SCIM Group Member sub-resource */
export interface ScimGroupMember {
  value: string;
  display?: string;
  $ref?: string;
}

/** SCIM Group Resource (RFC 7643 §4.2) */
export interface ScimGroup {
  schemas: string[];
  id: string;
  displayName: string;
  members?: ScimGroupMember[];
  meta: ScimMeta;
}

/** SCIM List Response (RFC 7644 §3.4.2) */
export interface ScimListResponse<T> {
  schemas: string[];
  totalResults: number;
  itemsPerPage: number;
  startIndex: number;
  Resources: T[];
}

/** SCIM PatchOp Operation (RFC 7644 §3.5.2) */
export interface ScimPatchOperation {
  op: "add" | "remove" | "replace";
  path?: string;
  value?: unknown;
}

/** SCIM PatchOp Request (RFC 7644 §3.5.2) */
export interface ScimPatchRequest {
  schemas: string[];
  Operations: ScimPatchOperation[];
}

/** SCIM Error Response (RFC 7644 §3.12) */
export interface ScimErrorResponse {
  schemas: string[];
  status: string;
  scimType?: string;
  detail: string;
}

/** SCIM filter operators we support */
export type ScimFilterOp = "eq";

/** Parsed SCIM filter expression */
export interface ScimFilter {
  attribute: string;
  op: ScimFilterOp;
  value: string;
}

/** SCIM token auth result */
export interface ScimAuthContext {
  tenantId: string;
  tokenId: string;
}

/** Supported SCIM filter attributes */
export const SUPPORTED_FILTER_ATTRIBUTES = [
  "userName",
  "emails.value",
  "externalId",
  "active",
] as const;

/** Build a SCIM User resource from database rows */
export function buildScimUser(params: {
  id: string;
  userName: string;
  externalId?: string;
  givenName?: string;
  familyName?: string;
  displayName?: string;
  email: string;
  active: boolean;
  createdAt: string;
  lastModified: string;
  baseUrl: string;
}): ScimUser {
  return {
    schemas: [SCIM_SCHEMAS.USER],
    id: params.id,
    ...(params.externalId && { externalId: params.externalId }),
    userName: params.userName,
    name: {
      givenName: params.givenName ?? "",
      familyName: params.familyName ?? "",
      formatted:
        [params.givenName, params.familyName].filter(Boolean).join(" ") || "",
    },
    displayName:
      params.displayName ||
      [params.givenName, params.familyName].filter(Boolean).join(" ") ||
      params.userName,
    emails: [{ value: params.email, type: "work", primary: true }],
    active: params.active,
    meta: {
      resourceType: "User",
      created: params.createdAt,
      lastModified: params.lastModified,
      location: `${params.baseUrl}/scim/v2/Users/${params.id}`,
    },
  };
}

/** Build a SCIM Group resource from database rows */
export function buildScimGroup(params: {
  id: string;
  displayName: string;
  members?: ScimGroupMember[];
  createdAt: string;
  lastModified: string;
  baseUrl: string;
}): ScimGroup {
  return {
    schemas: [SCIM_SCHEMAS.GROUP],
    id: params.id,
    displayName: params.displayName,
    members: params.members ?? [],
    meta: {
      resourceType: "Group",
      created: params.createdAt,
      lastModified: params.lastModified,
      location: `${params.baseUrl}/scim/v2/Groups/${params.id}`,
    },
  };
}

/** Build a SCIM List Response */
export function buildListResponse<T>(params: {
  resources: T[];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
}): ScimListResponse<T> {
  return {
    schemas: [SCIM_SCHEMAS.LIST_RESPONSE],
    totalResults: params.totalResults,
    itemsPerPage: params.itemsPerPage,
    startIndex: params.startIndex,
    Resources: params.resources,
  };
}

/** Parse a simple SCIM filter string (only supports "attribute eq value") */
export function parseScimFilter(
  filterStr: string | null,
): ScimFilter | null {
  if (!filterStr) return null;

  // SCIM filter format: attribute op "value"
  const match = filterStr.match(
    /^(\w+(?:\.\w+)?)\s+(eq)\s+"([^"]*)"$/i,
  );
  if (!match) {
    // Try without quotes for boolean values: active eq true
    const boolMatch = filterStr.match(
      /^(\w+)\s+(eq)\s+(true|false)$/i,
    );
    if (!boolMatch) return null;
    return {
      attribute: boolMatch[1],
      op: boolMatch[2].toLowerCase() as ScimFilterOp,
      value: boolMatch[3].toLowerCase(),
    };
  }

  return {
    attribute: match[1],
    op: match[2].toLowerCase() as ScimFilterOp,
    value: match[3],
  };
}
