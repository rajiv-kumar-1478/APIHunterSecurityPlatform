const DEFAULT_API_BASE_URL = "http://localhost:5000";
const CSRF_ENDPOINT = "/api/v1/auth/csrf";
const CSRF_HEADER = "X-CSRF-TOKEN";
const INVALID_CSRF_CODE = "INVALID_CSRF_TOKEN";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function normalizeApiBaseUrl(value: string | undefined): string {
  const configuredValue = value?.trim() || DEFAULT_API_BASE_URL;
  return configuredValue.replace(/\/+$/, "");
}

export const API_BASE_URL = normalizeApiBaseUrl(process.env.NEXT_PUBLIC_API_URL);

export function buildApiUrl(path: string): string {
  const normalizedPath = path.trim();
  if (!normalizedPath) return API_BASE_URL;
  return `${API_BASE_URL}/${normalizedPath.replace(/^\/+/, "")}`;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getStringProperty(value: unknown, property: string): string | undefined {
  if (!isRecord(value)) return undefined;
  const candidate = value[property];
  return typeof candidate === "string" && candidate.trim() ? candidate : undefined;
}

export function getResponseMessage(body: unknown, fallback: string): string {
  return (
    getStringProperty(body, "message") ??
    getStringProperty(body, "title") ??
    getStringProperty(body, "detail") ??
    fallback
  );
}

export async function parseResponseText(response: Response): Promise<string | null> {
  const text = await response.text();
  return text.trim() ? text : null;
}

export async function parseJsonResponse<T>(response: Response): Promise<T | null> {
  const text = await parseResponseText(response);
  if (text === null) return null;

  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

export async function parseResponseBody(response: Response): Promise<unknown> {
  const text = await parseResponseText(response);
  if (text === null) return null;

  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  const trimmed = text.trim();
  const looksLikeJson =
    contentType.includes("json") ||
    trimmed.startsWith("{") ||
    trimmed.startsWith("[") ||
    trimmed === "null" ||
    trimmed === "true" ||
    trimmed === "false";

  if (looksLikeJson) {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return text;
    }
  }

  return text;
}

interface ApiErrorOptions {
  status: number;
  statusText: string;
  url: string;
  body: unknown;
  code?: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly statusText: string;
  readonly url: string;
  readonly body: unknown;
  readonly code?: string;

  constructor(message: string, options: ApiErrorOptions) {
    super(message);
    this.name = "ApiError";
    this.status = options.status;
    this.statusText = options.statusText;
    this.url = options.url;
    this.body = options.body;
    this.code = options.code;
  }

  static fromResponse(response: Response, body: unknown, fallbackMessage?: string): ApiError {
    const fallback =
      fallbackMessage ??
      `Request failed with status ${response.status}${response.statusText ? ` ${response.statusText}` : ""}.`;

    return new ApiError(getResponseMessage(body, fallback), {
      status: response.status,
      statusText: response.statusText,
      url: response.url,
      body,
      code: getStringProperty(body, "code"),
    });
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

export function getErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) return error.message;
  return fallback;
}

let csrfToken: string | null = null;
let csrfBootstrapPromise: Promise<string> | null = null;
let authStateVersion = 0;

function setCsrfToken(token: string): string {
  csrfToken = token;
  return token;
}

async function requestCsrfToken(signal?: AbortSignal): Promise<string> {
  const response = await fetch(buildApiUrl(CSRF_ENDPOINT), {
    method: "GET",
    credentials: "include",
    headers: { Accept: "application/json" },
    signal,
  });
  const body = await parseResponseBody(response);

  if (!response.ok) {
    throw ApiError.fromResponse(response, body, "Failed to initialize request protection.");
  }

  const token = getStringProperty(body, "csrfToken");
  if (!token) {
    throw new ApiError("The CSRF bootstrap response did not include a token.", {
      status: response.status,
      statusText: response.statusText,
      url: response.url,
      body,
    });
  }

  return token;
}

function startCsrfBootstrap(signal?: AbortSignal): Promise<string> {
  const stateVersion = authStateVersion;
  const bootstrap = requestCsrfToken(signal)
    .then((token) => {
      if (stateVersion === authStateVersion) setCsrfToken(token);
      return token;
    })
    .finally(() => {
      if (csrfBootstrapPromise === bootstrap) csrfBootstrapPromise = null;
    });

  csrfBootstrapPromise = bootstrap;
  return bootstrap;
}

export function ensureCsrfToken(signal?: AbortSignal): Promise<string> {
  if (csrfToken) return Promise.resolve(csrfToken);
  return csrfBootstrapPromise ?? startCsrfBootstrap(signal);
}

export function refreshCsrfToken(signal?: AbortSignal): Promise<string> {
  csrfToken = null;
  csrfBootstrapPromise = null;
  authStateVersion += 1;
  return startCsrfBootstrap(signal);
}

export function primeCsrfToken(token: string): void {
  const normalizedToken = token.trim();
  if (!normalizedToken) return;

  authStateVersion += 1;
  csrfBootstrapPromise = null;
  setCsrfToken(normalizedToken);
}

export function clearAuthClientState(): void {
  authStateVersion += 1;
  csrfToken = null;
  csrfBootstrapPromise = null;
}

function isUnsafeMethod(method: string | undefined): boolean {
  return !SAFE_METHODS.has((method ?? "GET").toUpperCase());
}

async function sendRequest(
  path: string,
  options: RequestInit,
  unsafe: boolean,
  requestCsrfTokenValue: string | null,
): Promise<Response> {
  const headers = new Headers(options.headers);

  if (unsafe && requestCsrfTokenValue) {
    headers.set(CSRF_HEADER, requestCsrfTokenValue);
  } else {
    headers.delete(CSRF_HEADER);
  }

  return fetch(buildApiUrl(path), {
    ...options,
    credentials: "include",
    headers,
  });
}

async function isExplicitAntiforgeryRejection(response: Response): Promise<boolean> {
  if (response.status !== 400) return false;

  const body = await parseResponseBody(response.clone());
  return getStringProperty(body, "code") === INVALID_CSRF_CODE;
}

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const unsafe = isUnsafeMethod(options.method);
  const initialToken = unsafe ? await ensureCsrfToken(options.signal ?? undefined) : null;
  const response = await sendRequest(path, options, unsafe, initialToken);

  if (!unsafe || !(await isExplicitAntiforgeryRejection(response))) {
    return response;
  }

  const refreshedToken = await refreshCsrfToken(options.signal ?? undefined);
  return sendRequest(path, options, true, refreshedToken);
}

export async function apiRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await apiFetch(path, options);
  const body = await parseResponseBody(response);

  if (!response.ok) {
    throw ApiError.fromResponse(response, body);
  }

  return body as T;
}
