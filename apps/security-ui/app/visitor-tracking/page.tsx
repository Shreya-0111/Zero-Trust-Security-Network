"use client"

import { useEffect, useMemo, useState } from "react"
import { MapIcon, Clock } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { ScrollArea } from "@/components/ui/scroll-area"
import { getActiveVisitors, HttpError } from "@/lib/api"
import { useSession } from "@/hooks/use-session"
import AccessDenied from "@/components/access-denied"

export default function VisitorTrackingPage() {
  const { loading: sessionLoading, authenticated, user } = useSession({ redirectToLogin: true })
  const [rawVisitors, setRawVisitors] = useState<any[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const unauthorized = !sessionLoading && authenticated && user?.role !== "admin"

  useEffect(() => {
    if (sessionLoading || !authenticated) return
    if (user?.role !== "admin") return

    let cancelled = false
    async function run() {
      setIsLoading(true)
      setError(null)
      try {
        const res = await getActiveVisitors()
        if (cancelled) return
        setRawVisitors(res.visitors || [])
      } catch (e) {
        if (cancelled) return
        setError(e instanceof HttpError ? e.message : "Failed to load visitors")
      } finally {
        if (!cancelled) setIsLoading(false)
      }
    }

    run()
    return () => {
      cancelled = true
    }
  }, [authenticated, sessionLoading, user?.role])

  const visitors = useMemo(() => {
    return (rawVisitors || []).map((v: any) => {
      const expectedExit = v.expectedExitTime || v.expected_exit_time
      let timeRemaining = ""
      if (expectedExit) {
        const end = new Date(expectedExit).getTime()
        const diff = end - Date.now()
        const mins = Math.floor(Math.abs(diff) / 60000)
        const secs = Math.floor((Math.abs(diff) % 60000) / 1000)
        const mm = String(mins).padStart(2, "0")
        const ss = String(secs).padStart(2, "0")
        timeRemaining = `${diff < 0 ? "-" : ""}${mm}:${ss}`
      }

      const compliance = Number(v.routeCompliance?.complianceScore ?? v.route_compliance?.compliance_score ?? 0)
      const progress = Number.isFinite(compliance) ? Math.max(0, Math.min(100, compliance)) : 0

      const destination = v.assignedRoute?.routeDescription || v.assigned_route?.route_description || ""

      return {
        id: v.visitorId || v.visitor_id || v.id,
        name: v.name || "Visitor",
        host: v.hostName || v.host_name || "",
        destination: destination || "",
        progress,
        timeRemaining: timeRemaining || "N/A",
        status: v.status || "active",
        photo: v.photo || "/placeholder.svg",
      }
    })
  }, [rawVisitors])

  if (unauthorized) {
    return <AccessDenied required={["admin"]} />
  }

  return (
    <div className="h-screen bg-background flex flex-col">
      {/* Header */}
      <header className="h-16 border-b border-border bg-card/50 backdrop-blur-md flex items-center justify-between px-6 shrink-0">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded bg-warning/10">
              <MapIcon className="w-5 h-5 text-warning" />
            </div>
            <span className="font-bold text-lg">LIVE TRACKING</span>
          </div>
          <Badge variant="outline" className="bg-warning/10 text-warning border-warning/20">
            {isLoading ? "..." : `${visitors.length} ACTIVE VISITORS`}
          </Badge>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden">
        <aside className="w-full border-l border-border bg-card/30 backdrop-blur-sm flex flex-col shrink-0">
          <ScrollArea className="flex-1">
            <div className="p-4 space-y-4">
              {error && (
                <div className="text-xs text-destructive border border-destructive/30 bg-destructive/10 rounded-md p-3">
                  {error}
                </div>
              )}
              {isLoading && (
                <div className="text-xs text-muted-foreground">Loading visitors...</div>
              )}
              {visitors.map((visitor) => (
                <Card
                  key={visitor.id}
                  className={`glass-card overflow-hidden transition-all hover:border-border/80 ${
                    visitor.status === "Alert" ? "border-destructive/50 bg-destructive/5" : ""
                  }`}
                >
                  <CardContent className="p-4 space-y-4">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className="relative">
                          <img
                            src={visitor.photo || "/placeholder.svg"}
                            alt={visitor.name}
                            className="w-10 h-10 rounded-full border-2 border-border"
                          />
                          <div
                            className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-card ${
                              visitor.status === "Alert"
                                ? "bg-destructive"
                                : visitor.status === "Completed"
                                  ? "bg-success"
                                  : visitor.status === "Delayed"
                                    ? "bg-warning"
                                    : "bg-primary"
                            }`}
                          />
                        </div>
                        <div>
                          <h4 className="text-sm font-bold">{visitor.name}</h4>
                          <p className="text-[10px] text-muted-foreground uppercase">Host: {visitor.host}</p>
                        </div>
                      </div>
                      <Badge
                        variant={visitor.status === "Alert" ? "destructive" : "outline"}
                        className="text-[10px] h-5"
                      >
                        {visitor.status}
                      </Badge>
                    </div>

                    <div className="space-y-2">
                      <div className="flex justify-between text-[10px] font-bold uppercase">
                        <span className="text-muted-foreground">Route Progress</span>
                        <span>{visitor.progress}%</span>
                      </div>
                      <Progress
                        value={visitor.progress}
                        className="h-1"
                        indicatorClassName={
                          visitor.status === "Alert"
                            ? "bg-destructive"
                            : visitor.status === "Delayed"
                              ? "bg-warning"
                              : "bg-accent"
                        }
                      />
                    </div>

                    <div className="flex items-center justify-between text-[10px]">
                      <div className="flex items-center gap-1.5 text-muted-foreground">
                        <Clock className="w-3 h-3" />
                        <span>Est. Remaining:</span>
                        <span
                          className={`font-mono font-bold ${visitor.timeRemaining.startsWith("-") ? "text-destructive" : "text-foreground"}`}
                        >
                          {visitor.timeRemaining}
                        </span>
                      </div>
                      <div className="flex items-center gap-1.5 text-muted-foreground">
                        <MapIcon className="w-3 h-3" />
                        <span>
                          To: <span className="text-foreground">{visitor.destination}</span>
                        </span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </ScrollArea>
        </aside>
      </div>
    </div>
  )
}
