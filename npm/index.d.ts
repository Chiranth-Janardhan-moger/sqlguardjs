export type ThreatLabel =
  | 'benign'
  | 'sqli'
  | 'xss'
  | 'schema_violation'
  | 'rate_limit_escalation'
  | 'dos'
  | string;

export type DetectionLevel = 'strict' | 'balanced' | 'permissive';
export type EnforcementMode = 'block' | 'log' | 'observe' | 'monitor' | 'dry-run' | 'dryrun';
export type AllowPattern = string | RegExp | ((value: string, req?: any) => boolean);

export interface DetectionMatch {
  id: string;
  label: string;
  confidence: number;
}

export interface DetectionResult {
  label: ThreatLabel;
  confidence: number;
  scores: {
    sqli: number;
    xss: number;
  };
  matches: DetectionMatch[];
}

export interface SqlGuardJSEvent {
  type: 'sqlguardjs.threat';
  timestamp: string;
  action: 'block' | 'observe' | string;
  blocked: boolean;
  dryRun: boolean;
  requestId: string | null;
  method: string | null;
  url: string;
  route: string;
  ip: string;
  label: ThreatLabel;
  confidence: number;
  path: string;
  matches: DetectionMatch[];
  matchedSignalIds: string[];
  payloadPreview: string;
  payloadLength: number;
  reason: string | null;
}

export interface SqlGuardJSRateLimitEvent extends Omit<SqlGuardJSEvent, 'type'> {
  type: 'sqlguardjs.rate_limit';
}

export type SqlGuardJSLogEvent = SqlGuardJSEvent | SqlGuardJSRateLimitEvent;

export interface SqlGuardJSLearningEvent {
  type: 'sqlguardjs.learning';
  timestamp: string;
  requestId: string | null;
  method: string | null;
  url: string;
  route: string;
  ip: string;
  label: ThreatLabel;
  confidence: number;
  path: string;
  matches: DetectionMatch[];
  matchedSignalIds: string[];
  clusterKey: string;
  payloadPreview: string;
  payloadLength: number;
}

export interface SqlGuardJSCallbackErrorContext {
  type: 'sqlguardjs.callback_error';
  timestamp: string;
  hook: string;
  message: string;
  eventType: string | null;
  eventLabel: ThreatLabel | null;
  eventPath: string | null;
}

export type SqlGuardJSStoredLogEvent = SqlGuardJSLogEvent | SqlGuardJSLearningEvent;

export interface SqlGuardJSLogStore {
  maxLogs?: number;
  add(event: SqlGuardJSStoredLogEvent): void;
  list(): SqlGuardJSStoredLogEvent[];
  clear?(): void;
}

export interface LogsHandlerOptions {
  limit?: number;
}

export interface SchemaRule {
  allowed?: string[];
  fields?: string[];
  required?: string[];
  allowUnknown?: boolean;
}

export type SchemaSource = string[] | SchemaRule;

export interface RouteSchema {
  query?: SchemaSource;
  body?: SchemaSource;
  params?: SchemaSource;
  headers?: SchemaSource;
  cookies?: SchemaSource;
}

export interface LearningOptions {
  enabled?: boolean;
  onEvent?: (event: SqlGuardJSLearningEvent, req: any) => void | Promise<void>;
}

export interface RouteDetectionOptions {
  level?: DetectionLevel;
  detectionLevel?: DetectionLevel;
  threshold?: number;
  suspiciousThreshold?: number;
  maxSuspiciousRequests?: number;
}

export interface SqlGuardJSAllowlist {
  routes?: AllowPattern[];
  params?: AllowPattern[] | Record<string, AllowPattern[]>;
  parameters?: AllowPattern[] | Record<string, AllowPattern[]>;
  routeLevels?: Record<string, DetectionLevel | RouteDetectionOptions>;
}

export interface ExpressMiddlewareOptions {
  level?: DetectionLevel;
  detectionLevel?: DetectionLevel;
  mode?: EnforcementMode;
  threshold?: number;
  suspiciousThreshold?: number;
  rateLimitWindowMs?: number;
  maxSuspiciousRequests?: number;
  maxRateLimitCapacity?: number;
  maxRateLimitEventsPerKey?: number;
  rateLimitKey?: (req: any) => string | null | undefined | Promise<string | null | undefined>;
  dryRun?: boolean;
  logRequests?: boolean;
  logs?: boolean;
  maxLogs?: number;
  exposeLogs?: boolean;
  logsPath?: string;
  logStore?: SqlGuardJSLogStore;
  logAttacks?: boolean | ((messageOrEvent: string | SqlGuardJSLogEvent, event?: SqlGuardJSLogEvent) => void | Promise<void>);
  logFormat?: 'text' | 'json';
  jsonLogs?: boolean;
  onThreat?: (event: SqlGuardJSEvent, req: any) => void | Promise<void>;
  onLearningEvent?: (event: SqlGuardJSLearningEvent, req: any) => void | Promise<void>;
  onCallbackError?: (error: unknown, context: SqlGuardJSCallbackErrorContext) => void | Promise<void>;
  learning?: boolean | LearningOptions;
  blockStatus?: number;
  skip?: (req: any) => boolean | Promise<boolean>;
  scanQuery?: boolean;
  scanBody?: boolean;
  scanHeaders?: boolean;
  scanCookies?: boolean;
  scanParams?: boolean;
  scanKeys?: boolean;
  scanRawBody?: boolean;
  allowRoutes?: AllowPattern[];
  allowedRoutes?: AllowPattern[];
  allowParams?: AllowPattern[] | Record<string, AllowPattern[]>;
  allowedParams?: AllowPattern[] | Record<string, AllowPattern[]>;
  allowParameters?: AllowPattern[] | Record<string, AllowPattern[]>;
  allowlist?: SqlGuardJSAllowlist;
  routeLevels?: Record<string, DetectionLevel | RouteDetectionOptions>;
  routeDetectionLevels?: Record<string, DetectionLevel | RouteDetectionOptions>;
  routeThresholds?: Record<string, DetectionLevel | RouteDetectionOptions>;
  maxDepth?: number;
  maxFields?: number;
  maxPayloadLength?: number;
  maxDecodeIterations?: number;
  maxLogPayloadLength?: number;
  redactKeys?: string[];
  getRequestId?: (req: any) => string | null;
  schema?: RouteSchema;
  schemas?: Record<string, RouteSchema>;
  detector?: Detector;
}

export interface SecureRouterOptions extends ExpressMiddlewareOptions {
  routerOptions?: Record<string, unknown>;
  globalOptions?: ExpressMiddlewareOptions;
  routeOptions?: ExpressMiddlewareOptions;
}

export type RequestHandler = (req: any, res: any, next: any) => any;

export class Detector {
  constructor(options?: { maxPayloadLength?: number; maxDecodeIterations?: number });
  decodeDeeply(payload: unknown): string;
  normalizePayload(payload: unknown, options?: { sqlCommentMode?: 'space' | 'remove' | 'preserve' }): string;
  payloadVariants(payload: unknown): string[];
  detect(payload: unknown): DetectionResult;
}

export interface SqlGuardJSInstance {
  detector: Detector;
  logStore: SqlGuardJSLogStore;
  global(overrides?: ExpressMiddlewareOptions): RequestHandler;
  route(overrides?: ExpressMiddlewareOptions): RequestHandler;
  verify(overrides?: ExpressMiddlewareOptions): RequestHandler;
  middleware(overrides?: ExpressMiddlewareOptions): RequestHandler;
  nestjs(overrides?: ExpressMiddlewareOptions): RequestHandler;
  logs(): SqlGuardJSStoredLogEvent[];
  clearLogs(): void;
  logsHandler(options?: LogsHandlerOptions): RequestHandler;
  mountLogs(app: any, path?: string, options?: LogsHandlerOptions): any;
}

export interface SqlQueryGuardOptions {
  level?: DetectionLevel;
  detectionLevel?: DetectionLevel;
  threshold?: number;
  maxPayloadLength?: number;
  maxDecodeIterations?: number;
  detector?: Detector;
}

export interface PayloadEvaluationSample {
  payload?: unknown;
  text?: unknown;
  value?: unknown;
  label?: string;
  expected?: string;
  kind?: string;
}

export interface PayloadEvaluationResult {
  payload: string;
  expectedMalicious: boolean | null;
  blocked: boolean;
  result: DetectionResult;
}

export interface PayloadEvaluationReport {
  threshold: number;
  summary: {
    total: number;
    blocked: number;
    allowed: number;
    labeled: number;
    falsePositives: number;
    falseNegatives: number;
    truePositives: number;
    trueNegatives: number;
    falsePositiveRate: number;
    falseNegativeRate: number;
  };
  results: PayloadEvaluationResult[];
}

export class SqlGuardJSQueryError extends Error {
  result: DetectionResult;
}

export function scanSqlQuery(query: string, options?: SqlQueryGuardOptions): DetectionResult;
export function assertSafeSqlQuery(query: string, options?: SqlQueryGuardOptions): DetectionResult;
export function evaluatePayloads(samples: Array<string | PayloadEvaluationSample>, options?: SqlQueryGuardOptions): PayloadEvaluationReport;
export function createMemoryLogStore(maxLogs?: number): SqlGuardJSLogStore;
export function createLogsHandler(logStore: SqlGuardJSLogStore, options?: LogsHandlerOptions): RequestHandler;
export function expressMiddleware(options?: ExpressMiddlewareOptions): RequestHandler;
export function nestjsMiddleware(options?: ExpressMiddlewareOptions): RequestHandler;
export function createNestMiddleware(options?: ExpressMiddlewareOptions): any;
export function sqlguardjs(options?: ExpressMiddlewareOptions): SqlGuardJSInstance;
export function secureRouter(options?: SecureRouterOptions): any;
