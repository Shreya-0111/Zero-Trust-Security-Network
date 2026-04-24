"use client"

import { useEffect, useState } from "react"
import { AlertTriangle, CheckCircle2, Loader2, ShieldAlert, ThumbsDown, ThumbsUp } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import AccessDenied from "@/components/access-denied"

import { useSession } from "@/hooks/use-session"
import { useToast } from "@/hooks/use-toast"
import {
  approveBreakGlassRequest,
  denyBreakGlassRequest,
  getAvailableResourceSegments,
  getBreakGlassPendingRequests,
  submitBreakGlassRequest,
  HttpError,
} from "@/lib/api"

export default function EmergencyAccessPage() {
  const { loading: sessionLoading, authenticated, user } = useSession({ redirectToLogin: true })
  const { toast } = useToast()
  const isAdmin = user?.role === "admin"
  const unauthorized = !sessionLoading && authenticated && user?.role === "student"

  const [segments, setSegments] = useState<Array<{ segmentId: string; name: string; securityLevel?: number }>>([])
  const [loadingSegments, setLoadingSegments] = useState(true)
  const [selectedResources, setSelectedResources] = useState<string[]>([])
  const [emergencyType, setEmergencyType] = useState<string>("")
  const [urgencyLevel, setUrgencyLevel] = useState<string>("critical")
  const [estimatedDuration, setEstimatedDuration] = useState<string>("0.5")
  const [justification, setJustification] = useState<string>("")
  const [ack, setAck] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState<any | null>(null)
  const [error, setError] = useState<string | null>(null)

  const [pending, setPending] = useState<any[]>([])
  const [loadingPending, setLoadingPending] = useState(false)
  const [myRequests, setMyRequests] = useState<any[]>([])
  const [loadingMyRequests, setLoadingMyRequests] = useState(false)

  useEffect(() => {
    if (unauthorized) return
    if (sessionLoading || !authenticated) return
    let cancelled = false
    async function run() {
      setLoadingSegments(true)
      setError(null)
      try {
        const res = await getAvailableResourceSegments()
        if (cancelled) return
        setSegments(res.segments || [])
      } catch (e) {
        if (cancelled) return
        setError(e instanceof HttpError ? e.message : "Failed to load resources")
      } finally {
        if (!cancelled) setLoadingSegments(false)
      }
    }
    run()
    return () => {
      cancelled = true
    }
  }, [authenticated, sessionLoading, unauthorized])

  const refreshPending = async () => {
    if (!isAdmin) return
    setLoadingPending(true)
    setError(null)
    try {
      const res = await getBreakGlassPendingRequests()
      setPending(res.requests || [])
    } catch (e) {
      setError(e instanceof HttpError ? e.message : "Failed to load pending requests")
    } finally {
      setLoadingPending(false)
    }
  }

  const refreshMyRequests = async () => {
    setLoadingMyRequests(true)
    try {
      const { getMyBreakGlassRequests } = await import("@/lib/api")
      const res = await getMyBreakGlassRequests()
      setMyRequests(res.requests || [])
    } catch (e) {
      console.error("Failed to load my requests", e)
    } finally {
      setLoadingMyRequests(false)
    }
  }

  useEffect(() => {
    if (sessionLoading || !authenticated) return
    if (isAdmin) refreshPending()
    refreshMyRequests()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authenticated, isAdmin, sessionLoading])


  if (unauthorized) {
    return <AccessDenied required={["admin", "faculty", "user"]} />
  }

  const canSubmit =
    ack &&
    !!emergencyType &&
    justification.trim().length >= 100 &&
    selectedResources.length > 0

  return (
    <div className="min-h-screen bg-background p-6 md:p-12">
      <div className="max-w-5xl mx-auto space-y-8">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-destructive/10 text-destructive">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div className="flex-1">
            <h1 className="text-2xl font-bold">Emergency Break-Glass</h1>
            <p className="text-sm text-muted-foreground">Request temporary emergency access with audit trail.</p>
          </div>
          {isAdmin && <Badge variant="outline">ADMIN</Badge>}
        </div>

        {error && (
          <div className="text-xs text-destructive border border-destructive/30 bg-destructive/10 rounded-md p-3">
            {error}
          </div>
        )}

        <div className="grid lg:grid-cols-5 gap-6">
          <div className="lg:col-span-3 space-y-6">
            <Card className="bg-card border-border">
              <CardHeader>
                <CardTitle className="text-sm">Submit Request</CardTitle>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="grid md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Emergency Type</Label>
                    <Select value={emergencyType} onValueChange={setEmergencyType}>
                      <SelectTrigger className="bg-secondary/50">
                        <SelectValue placeholder="Select type" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="system_outage">System Outage</SelectItem>
                        <SelectItem value="security_incident">Security Incident</SelectItem>
                        <SelectItem value="critical_maintenance">Critical Maintenance</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Estimated Duration (hours)</Label>
                    <Select value={estimatedDuration} onValueChange={setEstimatedDuration}>
                      <SelectTrigger className="bg-secondary/50">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="0.25">0.25</SelectItem>
                        <SelectItem value="0.5">0.5</SelectItem>
                        <SelectItem value="1">1</SelectItem>
                        <SelectItem value="2">2</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Urgency</Label>
                  <Select value={urgencyLevel} onValueChange={setUrgencyLevel}>
                    <SelectTrigger className="bg-secondary/50">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label>Justification (min 100 chars)</Label>
                    <span className="text-[10px] text-muted-foreground">{justification.length}/1000</span>
                  </div>
                  <Textarea
                    value={justification}
                    onChange={(e) => setJustification(e.target.value)}
                    maxLength={1000}
                    className="bg-secondary/50 min-h-[140px]"
                    placeholder="Describe the incident and why emergency access is required..."
                  />
                </div>

                <div className="space-y-2">
                  <Label>Required Resources</Label>
                  <div className="rounded-md border border-border bg-secondary/20 p-3 space-y-2">
                    {loadingSegments ? (
                      <div className="text-xs text-muted-foreground">Loading resources...</div>
                    ) : (
                      (segments || []).slice(0, 12).map((s) => {
                        const id = s.segmentId
                        const checked = selectedResources.includes(id)
                        return (
                          <div key={id} className="flex items-center gap-2">
                            <Checkbox
                              id={id}
                              checked={checked}
                              onCheckedChange={(v) => {
                                const on = !!v
                                setSelectedResources((prev) => {
                                  if (on) return Array.from(new Set([...prev, id]))
                                  return prev.filter((x) => x !== id)
                                })
                              }}
                            />
                            <label htmlFor={id} className="text-xs text-muted-foreground">
                              {s.name} (Lvl {String(s.securityLevel ?? "-")})
                            </label>
                          </div>
                        )
                      })
                    )}
                  </div>
                  <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                    <AlertTriangle className="w-3 h-3" />
                    Select only the minimum resources required.
                  </div>
                </div>

                <div className="flex items-start gap-2">
                  <Checkbox id="ack" checked={ack} onCheckedChange={(v) => setAck(!!v)} />
                  <label htmlFor="ack" className="text-xs text-muted-foreground leading-relaxed">
                    I acknowledge this action will be monitored and audited.
                  </label>
                </div>

                <Button
                  className="w-full"
                  disabled={submitting || !canSubmit}
                  onClick={async () => {
                    setError(null)
                    setResult(null)
                    if (!canSubmit) {
                      setError("Please complete all required fields")
                      return
                    }
                    setSubmitting(true)
                    try {
                      const res = await submitBreakGlassRequest({
                        emergencyType,
                        urgencyLevel,
                        justification: justification.trim(),
                        requiredResources: selectedResources,
                        estimatedDuration: Number(estimatedDuration) || 0.5,
                      })
                      setResult(res)
                      if (isAdmin) await refreshPending()
                      await refreshMyRequests()
                    } catch (e) {
                      setError(e instanceof HttpError ? e.message : "Failed to submit request")
                    } finally {
                      setSubmitting(false)
                    }
                  }}
                >
                  {submitting ? (
                    <span className="inline-flex items-center">
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Submitting...
                    </span>
                  ) : (
                    "Request Emergency Access"
                  )}
                </Button>
              </CardContent>
            </Card>

            {result && (
              <Card className="bg-card border-border">
                <CardHeader>
                  <CardTitle className="text-sm">Submission</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-success" />
                    <div className="text-sm font-medium">Request submitted</div>
                  </div>
                  <pre className="text-[10px] bg-secondary/30 border border-border rounded-md p-3 overflow-auto max-h-40">
                    {JSON.stringify(result, null, 2)}
                  </pre>
                </CardContent>
              </Card>
            )}
          </div>

          <div className="lg:col-span-2 space-y-6">
            {isAdmin && (
              <Card className="bg-card border-border">
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle className="text-sm">Pending Approvals</CardTitle>
                  <Button size="sm" variant="outline" onClick={refreshPending} disabled={loadingPending}>
                    Refresh
                  </Button>
                </CardHeader>
                <CardContent className="space-y-3">
                  {loadingPending ? (
                    <div className="text-xs text-muted-foreground">Loading pending requests...</div>
                  ) : pending.length === 0 ? (
                    <div className="text-xs text-muted-foreground">No pending requests.</div>
                  ) : (
                    pending.slice(0, 10).map((r: any) => {
                      const id = r.requestId || r.id || r.request_id
                      const title = r.emergencyType || r.type || "request"
                      return (
                        <div key={String(id)} className="border border-border rounded-md p-3 bg-secondary/20 space-y-2">
                          <div className="flex items-center justify-between gap-2">
                            <div className="min-w-0">
                              <div className="text-xs font-semibold truncate">{String(title)}</div>
                              <div className="text-[10px] text-muted-foreground truncate">{String(id)}</div>
                            </div>
                            <div className="flex gap-2">
                              <Button
                                size="sm"
                                variant="secondary"
                                onClick={async () => {
                                  setError(null)
                                  try {
                                    await approveBreakGlassRequest(String(id), { comments: "Approved via UI" })
                                    toast({ title: "Approved", description: `Request ${String(id)} approved.` })
                                    await refreshPending()
                                  } catch (e) {
                                    setError(e instanceof HttpError ? e.message : "Approval failed")
                                    toast({
                                      variant: "destructive",
                                      title: "Approval failed",
                                      description: e instanceof HttpError ? e.message : "Approval failed",
                                    })
                                  }
                                }}
                              >
                                <ThumbsUp className="w-4 h-4" />
                              </Button>
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={async () => {
                                  setError(null)
                                  try {
                                    await denyBreakGlassRequest(String(id), { comments: "Denied via UI" })
                                    toast({ title: "Denied", description: `Request ${String(id)} denied.` })
                                    await refreshPending()
                                  } catch (e) {
                                    setError(e instanceof HttpError ? e.message : "Deny failed")
                                    toast({
                                      variant: "destructive",
                                      title: "Deny failed",
                                      description: e instanceof HttpError ? e.message : "Deny failed",
                                    })
                                  }
                                }}
                              >
                                <ThumbsDown className="w-4 h-4" />
                              </Button>
                            </div>
                          </div>
                          <div className="text-[10px] text-muted-foreground line-clamp-3">
                            {String(r.justification || r.reason || "")}
                          </div>
                        </div>
                      )
                    })
                  )}
                </CardContent>
              </Card>
            )}

            <Card className="bg-card border-border">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="text-sm">Your Requests & Active Sessions</CardTitle>
                <Button size="sm" variant="outline" onClick={refreshMyRequests} disabled={loadingMyRequests}>
                  Refresh
                </Button>
              </CardHeader>
              <CardContent className="space-y-3">
                {loadingMyRequests ? (
                  <div className="text-xs text-muted-foreground">Loading your requests...</div>
                ) : myRequests.length === 0 ? (
                  <div className="text-xs text-muted-foreground">You have no recent requests.</div>
                ) : (
                  myRequests.map((r: any) => {
                    const id = r.id || r.requestId
                    const status = r.status || "pending"
                    const isApproved = status === "approved"
                    const hasSession = !!r.emergencySession
                    
                    return (
                      <div key={String(id)} className="border border-border rounded-md p-3 bg-secondary/10 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="text-xs font-semibold">{r.emergencyType || "Emergency Access"}</div>
                          <Badge variant={status === "approved" ? "default" : status === "denied" ? "destructive" : "secondary"}>
                            {status.toUpperCase()}
                          </Badge>
                        </div>
                        
                        {isApproved && hasSession && (
                          <div className="p-2 bg-success/10 border border-success/30 rounded-md">
                            <div className="text-[10px] text-success font-bold flex items-center gap-1">
                              <CheckCircle2 className="w-3 h-3" /> SESSION ACTIVE
                            </div>
                            <div className="text-[9px] text-success/80 mt-1">
                              Resources unlocked: {r.requiredResources?.join(", ") || "All requested"}
                            </div>
                          </div>
                        )}
                        
                        <div className="text-[10px] text-muted-foreground italic truncate">
                          "{r.justification?.substring(0, 50)}..."
                        </div>
                        
                        {status === "pending" && (
                          <div className="text-[9px] text-muted-foreground">
                            Waiting for dual approval ({r.approvals?.length || 0}/2)
                          </div>
                        )}
                      </div>
                    )
                  })
                )}
              </CardContent>
            </Card>

          </div>
        </div>
      </div>
    </div>
  )
}
