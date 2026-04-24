export type ApiError = {
  code?: string
  message: string
}

export class HttpError extends Error {
  status: number
  data: unknown

  constructor(status: number, message: string, data: unknown) {
    super(message)
    this.status = status
    this.data = data
  }
}

function getCookie(name: string): string | null {
  if (typeof document === "undefined") return null
  const value = `; ${document.cookie}`
  const parts = value.split(`; ${name}=`)
  if (parts.length === 2) return parts.pop()!.split(";").shift() || null
  return null
}

function getApiBaseUrl(): string {
  const base =
    (typeof globalThis !== "undefined" &&
      (globalThis as any).process?.env?.NEXT_PUBLIC_API_URL) ||
    process.env.NEXT_PUBLIC_API_URL ||
    process.env.NEXT_PUBLIC_BACKEND_URL ||
    undefined
  return (base || "http://localhost:5001").replace(/\/$/, "")
}

export async function apiFetch<T>(
  path: string,
  options: RequestInit & { skipCsrf?: boolean } = {}
): Promise<T> {
  const { skipCsrf, headers, ...rest } = options

  const url = `${getApiBaseUrl()}${path.startsWith("/") ? path : `/${path}`}`

  const h = new Headers(headers)
  if (!h.has("Accept")) h.set("Accept", "application/json")

  const method = (rest.method || "GET").toUpperCase()
  const isMutating = ["POST", "PUT", "PATCH", "DELETE"].includes(method)

  if (isMutating && !skipCsrf) {
    const csrf = getCookie("csrf_token")
    if (csrf) h.set("X-CSRF-Token", csrf)
  }

  const res = await fetch(url, {
    ...rest,
    headers: h,
    credentials: "include",
  })

  const contentType = res.headers.get("content-type") || ""
  const isJson = contentType.includes("application/json")
  const data = isJson ? await res.json().catch(() => null) : await res.text().catch(() => "")

  if (!res.ok) {
    const message =
      (data && typeof data === "object" && "error" in (data as any) && (data as any).error?.message) ||
      (data && typeof data === "object" && "message" in (data as any) && (data as any).message) ||
      `Request failed (${res.status})`

    throw new HttpError(res.status, message, data)
  }

  return data as T
}

export type SessionStatusResponse = {
  success: boolean
  authenticated: boolean
  user?: {
    id: string
    email?: string
    name?: string
    role?: string
  }
}

export async function getSessionStatus() {
  return apiFetch<SessionStatusResponse>("/api/auth/session/status")
}

export async function logout() {
  return apiFetch<{ success: boolean; message?: string }>("/api/auth/logout", {
    method: "POST",
  })
}

export async function exchangeFirebaseIdToken(idToken: string) {
  return apiFetch<{ success: boolean; user?: any; csrfToken?: string }>("/api/auth/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ idToken }),
    skipCsrf: true,
  })
}

export async function signupUser(data: {
  idToken: string
  name: string
  role: string
  department?: string
  studentId?: string
}) {
  return apiFetch<{
    success: boolean
    message?: string
    user?: {
      id: string
      email?: string
      name?: string
      role?: string
      department?: string
      studentId?: string
      emailVerified?: boolean
    }
    sessionToken?: string
    csrfToken?: string
  }>("/api/auth/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
    skipCsrf: true,
  })
}

export type AuditLog = {
  id?: string
  timestamp?: string
  eventType?: string
  userId?: string
  userEmail?: string
  action?: string
  resource?: string
  result?: string
  severity?: string
  details?: any
}

export async function getAuditLogs(params?: {
  userId?: string
  eventType?: string
  severity?: string
  result?: string
  limit?: number
  offset?: number
}) {
  const qs = new URLSearchParams()
  if (params?.userId) qs.set("userId", params.userId)
  if (params?.eventType) qs.set("eventType", params.eventType)
  if (params?.severity) qs.set("severity", params.severity)
  if (params?.result) qs.set("result", params.result)
  if (params?.limit != null) qs.set("limit", String(params.limit))
  if (params?.offset != null) qs.set("offset", String(params.offset))

  const query = qs.toString()
  return apiFetch<{ success: boolean; logs: AuditLog[]; totalCount: number }>(
    `/api/admin/logs${query ? `?${query}` : ""}`
  )
}

export type PolicyRule = {
  policyId?: string
  name?: string
  description?: string
  rules?: any[]
  priority?: number
  isActive?: boolean
  createdAt?: string
  lastModified?: string
}

export async function getPolicyRules(includeInactive?: boolean) {
  const qs = new URLSearchParams()
  if (includeInactive) qs.set("includeInactive", "true")
  const query = qs.toString()
  return apiFetch<{ success: boolean; policies: PolicyRule[]; totalCount: number }>(
    `/api/policy/rules${query ? `?${query}` : ""}`
  )
}

export type ResourceSegment = {
  segmentId: string
  name: string
  description?: string
  securityLevel: number
  category?: string
  requiresJIT?: boolean
  isActive?: boolean
}

export async function getAvailableResourceSegments(params?: { jitOnly?: boolean }) {
  const qs = new URLSearchParams()
  if (params?.jitOnly) qs.set("jit_only", "true")
  const query = qs.toString()
  return apiFetch<{ success: boolean; segments: ResourceSegment[]; count: number }>(
    `/api/resource-segments/available${query ? `?${query}` : ""}`
  )
}

export type JitAccessDecision = {
  success: boolean
  requestId: string
  decision: "granted" | "denied" | "pending_approval"
  confidenceScore?: number
  message?: string
  expiresAt?: string
  requiresApproval?: boolean
  mfaRequired?: boolean
  riskAssessment?: any
  mlEvaluation?: any
  approvalRecommendations?: any[]
}

export async function submitJitAccessRequest(input: {
  resourceSegmentId: string
  justification: string
  duration: number
  urgency: "low" | "medium" | "high"
}) {
  return apiFetch<JitAccessDecision>("/api/jit-access/request", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  })
}

export async function getAdminJitRequests(params?: {
  status?: string
  userId?: string
  segmentId?: string
  limit?: number
  offset?: number
}) {
  const qs = new URLSearchParams()
  if (params?.status) qs.set("status", params.status)
  if (params?.userId) qs.set("user_id", params.userId)
  if (params?.segmentId) qs.set("segment_id", params.segmentId)
  if (params?.limit != null) qs.set("limit", String(params.limit))
  if (params?.offset != null) qs.set("offset", String(params.offset))
  const query = qs.toString()
  return apiFetch<{ success: boolean; requests: any[]; totalCount: number; limit: number; offset: number }>(
    `/api/admin/jit-access/requests${query ? `?${query}` : ""}`
  )
}

export async function approveAdminJitRequest(requestId: string, input?: { comments?: string; duration_override?: number }) {
  return apiFetch<any>(`/api/admin/jit-access/${requestId}/approve`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input || {}),
  })
}

export async function submitBreakGlassRequest(input: {
  emergencyType: string
  urgencyLevel: string
  justification: string
  requiredResources: string[]
  estimatedDuration: number
  mfaToken?: string
}) {
  return apiFetch<any>("/api/break-glass/emergency-request", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ...input,
      mfaToken: input.mfaToken || "dev-mode-token"
    }),
  })
}

export async function getBreakGlassAvailableAdministrators() {
  return apiFetch<{ success: boolean; administrators: any[]; count: number }>("/api/break-glass/available-administrators")
}

export async function getBreakGlassPendingRequests() {
  return apiFetch<{ success: boolean; requests: any[]; count: number }>("/api/break-glass/pending-requests")
}

export async function getMyBreakGlassRequests() {
  return apiFetch<{ success: boolean; requests: any[]; count: number }>("/api/break-glass/my-requests")
}


export async function approveBreakGlassRequest(requestId: string, input?: { comments?: string; mfaToken?: string }) {
  return apiFetch<any>(`/api/break-glass/requests/${requestId}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ...(input || {}),
      mfaToken: input?.mfaToken || "dev-mode-token"
    }),
  })
}

export async function denyBreakGlassRequest(requestId: string, input?: { comments?: string }) {
  return apiFetch<any>(`/api/break-glass/requests/${requestId}/deny`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input || {}),
  })
}

export async function getMonitoringHealth() {
  return apiFetch<any>("/api/monitoring/health")
}

export async function getMonitoringMetricsSummary() {
  return apiFetch<any>("/api/monitoring/metrics/summary")
}

export async function getMonitoringLogsSummary(hours?: number) {
  const qs = new URLSearchParams()
  if (hours != null) qs.set("hours", String(hours))
  const query = qs.toString()
  return apiFetch<any>(`/api/monitoring/logs/summary${query ? `?${query}` : ""}`)
}

export async function getActiveVisitors() {
  return apiFetch<any>("/api/visitors/active")
}

export async function listUserDevices(userId: string) {
  return apiFetch<{ success: boolean; devices: any[]; totalCount: number }>(`/api/devices/list/${userId}`)
}

export async function removeDevice(deviceId: string) {
  return apiFetch<any>(`/api/devices/${deviceId}`, { method: "DELETE" })
}

export async function registerDevice(input: {
  userId: string
  fingerprintData: Record<string, any>
  deviceName?: string
  mfaVerified?: boolean
}) {
  return apiFetch<any>("/api/devices/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  })
}

export async function registerVisitor(formData: FormData) {
  return apiFetch<any>("/api/visitors/register", {
    method: "POST",
    body: formData,
  })
}

export async function upsertPolicy(input: {
  policyId?: string
  name?: string
  description?: string
  rules?: any[]
  priority?: number
  isActive?: boolean
}) {
  return apiFetch<any>("/api/admin/policy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  })
}

export async function deletePolicy(policyId: string) {
  return apiFetch<any>(`/api/admin/policy/${policyId}`, { method: "DELETE" })
}
