"use client"

import { useEffect, useState } from "react"
import { Activity, FileText, HeartPulse, Loader2 } from "lucide-react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import AccessDenied from "@/components/access-denied"

import { useSession } from "@/hooks/use-session"
import { getMonitoringHealth, getMonitoringLogsSummary, getMonitoringMetricsSummary, HttpError } from "@/lib/api"

export default function SecurityMonitoringPage() {
  const { loading: sessionLoading, authenticated, user } = useSession({ redirectToLogin: true })
  const unauthorized = !sessionLoading && authenticated && user?.role !== "admin"

  const [loading, setLoading] = useState(true)
  const [health, setHealth] = useState<any | null>(null)
  const [metrics, setMetrics] = useState<any | null>(null)
  const [logs, setLogs] = useState<any | null>(null)
  const [error, setError] = useState<string | null>(null)

  const refresh = async () => {
    setLoading(true)
    setError(null)
    try {
      const [h, m, l] = await Promise.all([
        getMonitoringHealth(),
        getMonitoringMetricsSummary(),
        getMonitoringLogsSummary(24),
      ])
      setHealth(h)
      setMetrics(m)
      setLogs(l)
    } catch (e) {
      setError(e instanceof HttpError ? e.message : "Failed to load monitoring data")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (unauthorized) return
    if (sessionLoading || !authenticated) return
    if (user?.role !== "admin") return
    refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authenticated, sessionLoading, user?.role])

  if (unauthorized) return <AccessDenied required={["admin"]} />

  return (
    <div className="min-h-screen bg-background p-6 md:p-12">
      <div className="max-w-5xl mx-auto space-y-6">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Activity className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Security Monitoring</h1>
              <p className="text-sm text-muted-foreground">Operational health, metrics, and log summaries.</p>
            </div>
          </div>
          <Button variant="outline" onClick={refresh} disabled={loading}>
            {loading ? (
              <span className="inline-flex items-center">
                <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading
              </span>
            ) : (
              "Refresh"
            )}
          </Button>
        </div>

        {error && (
          <div className="text-xs text-destructive border border-destructive/30 bg-destructive/10 rounded-md p-3">
            {error}
          </div>
        )}

        <div className="grid md:grid-cols-3 gap-4">
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-sm inline-flex items-center gap-2">
                <HeartPulse className="w-4 h-4" /> Health
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              <pre className="bg-secondary/30 border border-border rounded-md p-3 overflow-auto max-h-48">
                {JSON.stringify(health, null, 2)}
              </pre>
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-sm inline-flex items-center gap-2">
                <Activity className="w-4 h-4" /> Metrics
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              <pre className="bg-secondary/30 border border-border rounded-md p-3 overflow-auto max-h-48">
                {JSON.stringify(metrics, null, 2)}
              </pre>
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-sm inline-flex items-center gap-2">
                <FileText className="w-4 h-4" /> Logs
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              <pre className="bg-secondary/30 border border-border rounded-md p-3 overflow-auto max-h-48">
                {JSON.stringify(logs, null, 2)}
              </pre>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
