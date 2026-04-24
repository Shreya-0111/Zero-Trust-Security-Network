"use client"

import { useEffect, useMemo, useState } from "react"
import { CheckCircle2, Loader2, ShieldCheck, AlertTriangle } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

import { useSession } from "@/hooks/use-session"
import { getAvailableResourceSegments, submitJitAccessRequest, HttpError } from "@/lib/api"
import AccessDenied from "@/components/access-denied"

export default function JITAccessPage() {
  const { loading: sessionLoading, authenticated, user } = useSession({ redirectToLogin: true })
  const unauthorized = !sessionLoading && authenticated && user?.role === "student"
  const [segments, setSegments] = useState<Array<{ segmentId: string; name: string; securityLevel?: number }>>([])
  const [loadingSegments, setLoadingSegments] = useState(true)
  const [segmentId, setSegmentId] = useState<string>("")
  const [duration, setDuration] = useState<string>("1")
  const [urgency, setUrgency] = useState<"low" | "medium" | "high">("medium")
  const [justification, setJustification] = useState("")
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState<any | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (unauthorized) return
    if (sessionLoading || !authenticated) return
    let cancelled = false
    async function run() {
      setLoadingSegments(true)
      setError(null)
      try {
        const res = await getAvailableResourceSegments({ jitOnly: true })
        if (cancelled) return
        setSegments(res.segments || [])
      } catch (e) {
        if (cancelled) return
        setError(e instanceof HttpError ? e.message : "Failed to load resource segments")
      } finally {
        if (!cancelled) setLoadingSegments(false)
      }
    }
    run()
    return () => {
      cancelled = true
    }
  }, [authenticated, sessionLoading, unauthorized])

  const selectedSegment = useMemo(() => {
    return segments.find((s) => s.segmentId === segmentId) || null
  }, [segmentId, segments])

  if (unauthorized) {
    return <AccessDenied required={["admin", "faculty", "user"]} />
  }

  return (
    <div className="min-h-screen bg-background p-6 md:p-12">
      <div className="max-w-3xl mx-auto space-y-6">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10">
            <ShieldCheck className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Just-in-Time Access</h1>
            <p className="text-sm text-muted-foreground">Request temporary elevated access to protected resources.</p>
          </div>
        </div>

        {error && (
          <div className="text-xs text-destructive border border-destructive/30 bg-destructive/10 rounded-md p-3">
            {error}
          </div>
        )}

        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-sm">Request</CardTitle>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="space-y-2">
              <Label>Resource Segment</Label>
              <Select value={segmentId} onValueChange={setSegmentId}>
                <SelectTrigger className="bg-secondary/50">
                  <SelectValue placeholder={loadingSegments ? "Loading..." : "Select a resource"} />
                </SelectTrigger>
                <SelectContent>
                  {(segments || []).map((s) => (
                    <SelectItem key={s.segmentId} value={s.segmentId}>
                      {s.name} (Lvl {String(s.securityLevel ?? "-")})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {selectedSegment && (
                <div className="text-[10px] text-muted-foreground">Selected: {selectedSegment.name}</div>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Duration (hours)</Label>
                <Select value={duration} onValueChange={setDuration}>
                  <SelectTrigger className="bg-secondary/50">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {[1, 2, 4, 8, 12, 24].map((h) => (
                      <SelectItem key={h} value={String(h)}>
                        {h}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Urgency</Label>
                <Select value={urgency} onValueChange={(v) => setUrgency(v as any)}>
                  <SelectTrigger className="bg-secondary/50">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>Justification (min 50 chars)</Label>
                <span className="text-[10px] text-muted-foreground">{justification.length}/500</span>
              </div>
              <Textarea
                value={justification}
                onChange={(e) => setJustification(e.target.value)}
                maxLength={500}
                className="bg-secondary/50 min-h-[120px]"
                placeholder="Describe why you need this access..."
              />
            </div>

            <Button
              className="w-full"
              disabled={submitting || !segmentId || justification.trim().length < 50}
              onClick={async () => {
                setError(null)
                setResult(null)
                if (!segmentId) {
                  setError("Select a resource segment")
                  return
                }
                if (justification.trim().length < 50) {
                  setError("Justification must be at least 50 characters")
                  return
                }
                setSubmitting(true)
                try {
                  const res = await submitJitAccessRequest({
                    resourceSegmentId: segmentId,
                    justification: justification.trim(),
                    duration: Number(duration) || 1,
                    urgency,
                  })
                  setResult(res)
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
                "Submit Request"
              )}
            </Button>
          </CardContent>
        </Card>

        {result && (
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-sm">Decision</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex items-center gap-2">
                {String(result.decision).toLowerCase() === "granted" ? (
                  <CheckCircle2 className="w-4 h-4 text-success" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-warning" />
                )}
                <div className="text-sm font-medium">{String(result.decision || "").toUpperCase()}</div>
              </div>
              {result.message && <div className="text-xs text-muted-foreground">{result.message}</div>}
              {result.expiresAt && <div className="text-xs text-muted-foreground">Expires: {result.expiresAt}</div>}
              {typeof result.confidenceScore === "number" && (
                <div className="text-xs text-muted-foreground">Confidence: {result.confidenceScore}%</div>
              )}
              {result.requestId && <div className="text-[10px] text-muted-foreground">Request ID: {result.requestId}</div>}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
