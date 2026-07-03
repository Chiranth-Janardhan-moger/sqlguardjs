export type ThreatLabel =
  | 'benign'
  | 'sqli'
  | 'xss'
  | 'schema_violation'
  | 'rate_limit_escalation'
  | 'rate_limit_sqli_heuristic'
  | 'dos'
  | string;

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

export interface SqlGuardEvent {
  type: 'sqlguard.threat';
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

export interface SqlGuardLearningEvent {
  type: 'sqlguard.learning';
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
  onEvent?: (event: SqlGuardLearningEvent, req: any) => void;
}

export interface ExpressMiddlewareOptions {
  threshold?: number;
  suspiciousThreshold?: number;
  mlEndpoint?: string | null;
  maxMlCalls?: number;
  rateLimitWindowMs?: number;
  maxSuspiciousRequests?: number;
  maxRateLimitCapacity?: number;
  dryRun?: boolean;
  logAttacks?: boolean | ((messageOrEvent: string | SqlGuardEvent, event?: SqlGuardEvent) => void);
  logFormat?: 'text' | 'json';
  jsonLogs?: boolean;
  onThreat?: (event: SqlGuardEvent, req: any) => void;
  onLearningEvent?: (event: SqlGuardLearningEvent, req: any) => void;
  learning?: boolean | LearningOptions;
  blockStatus?: number;
  skip?: (req: any) => boolean;
  scanQuery?: boolean;
  scanBody?: boolean;
  scanHeaders?: boolean;
  scanCookies?: boolean;
  scanParams?: boolean;
  scanKeys?: boolean;
  maxDepth?: number;
  maxFields?: number;
  maxPayloadLength?: number;
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
  constructor(options?: { maxPayloadLength?: number });
  decodeDeeply(payload: unknown): string;
  normalizePayload(payload: unknown, options?: { sqlCommentMode?: 'space' | 'remove' }): string;
  payloadVariants(payload: unknown): string[];
  detect(payload: unknown): DetectionResult;
}

export interface SqlGuardInstance {
  detector: Detector;
  global(overrides?: ExpressMiddlewareOptions): RequestHandler;
  route(overrides?: ExpressMiddlewareOptions): RequestHandler;
  verify(overrides?: ExpressMiddlewareOptions): RequestHandler;
  middleware(overrides?: ExpressMiddlewareOptions): RequestHandler;
}

export function expressMiddleware(options?: ExpressMiddlewareOptions): RequestHandler;
export function sqlguard(options?: ExpressMiddlewareOptions): SqlGuardInstance;
export function secureRouter(options?: SecureRouterOptions): any;
