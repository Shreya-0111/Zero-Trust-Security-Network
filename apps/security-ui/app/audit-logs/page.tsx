"use client"

import React from "react"

import { useEffect, useMemo, useState } from "react"
import {
  FileText,
  ChevronRight,
} from "lucide-react"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ScrollArea } from "@/components/ui/scroll-area"
import { getAuditLogs, HttpError } from "@/lib/api"
import { useSession } from "@/hooks/use-session"
import AccessDenied from "@/components/access-denied"

export default function AuditLogsPage() {
  const { loading: sessionLoading, authenticated, user } = useSession({ redirectToLogin: true })
  const [expandedRow, setExpandedRow] = useState<number | null>(null)
  const [logs, setLogs] = useState<any[]>([])
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
        const res = await getAuditLogs({ limit: 100, offset: 0 })
        if (cancelled) return
        setLogs(res.logs || [])
      } catch (e) {
        if (cancelled) return
        if (e instanceof HttpError) {
          setError(e.message)
        } else {
          setError("Failed to load audit logs")
        }
      } finally {
        if (!cancelled) setIsLoading(false)
      }
    }

    run()

    return () => {
      cancelled = true
    }
  }, [authenticated, sessionLoading, user?.role])

  const rows = useMemo(() => {
    return (logs || []).map((l, idx) => {
      return {
        _rowId: idx,
        timestamp: l.timestamp || "",
        type: l.eventType || l.type || "",
        user: l.userEmail || l.userId || l.user || "",
        action: l.action || "",
        resource: l.resource || "",
        result: l.result || "",
        severity: l.severity || "",
        context: l.details || l.context || {},
      }
    })
  }, [logs])

  if (unauthorized) {
    return <AccessDenied required={["admin"]} />
  }

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col">
      <header className="h-20 border-b border-border bg-card/50 backdrop-blur-md px-8 flex items-center justify-between sticky top-0 z-40">
        <div className="flex items-center gap-4">
          <div className="p-2 rounded-lg bg-primary/10">
            <FileText className="w-8 h-8 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Audit Log Viewer</h1>
            <p className="text-xs text-muted-foreground">Immutable Event Registry & Traceability</p>
          </div>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden">
        {/* Main Log Table */}
        <main className="flex-1 p-6 overflow-hidden">
          {error && (
            <div className="mb-4 text-xs text-destructive border border-destructive/30 bg-destructive/10 rounded-md p-3">
              {error}
            </div>
          )}
          <Card className="glass-card overflow-hidden h-full">
            <ScrollArea className="h-full">
              <div className="p-8">
                <Table className="border border-border rounded-xl overflow-hidden">
                  <TableHeader className="bg-secondary/30">
                    <TableRow className="border-border">
                      <TableHead className="w-[10px]"></TableHead>
                      <TableHead className="text-[10px] font-bold uppercase py-4">Timestamp</TableHead>
                      <TableHead className="text-[10px] font-bold uppercase">Event Type</TableHead>
                      <TableHead className="text-[10px] font-bold uppercase">Actor</TableHead>
                      <TableHead className="text-[10px] font-bold uppercase">Action</TableHead>
                      <TableHead className="text-[10px] font-bold uppercase">Result</TableHead>
                      <TableHead className="w-[10px]"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {isLoading ? (
                      <TableRow className="border-border">
                        <TableCell colSpan={7} className="text-xs text-muted-foreground py-10 text-center">
                          Loading...
                        </TableCell>
                      </TableRow>
                    ) : (
                      rows.map((log, index) => (
                        <React.Fragment key={log._rowId}>
                          <TableRow
                            className={`border-border hover:bg-secondary/20 cursor-pointer ${expandedRow === index ? "bg-secondary/20" : ""}`}
                            onClick={() => setExpandedRow(expandedRow === index ? null : index)}
                          >
                            <TableCell>
                              <div
                                className={`w-1 h-8 rounded-full ${log.severity === "critical" ? "bg-destructive" : log.severity === "high" ? "bg-warning" : "bg-primary"}`}
                              />
                            </TableCell>
                            <TableCell className="text-xs font-mono py-4 text-muted-foreground whitespace-nowrap">
                              {log.timestamp}
                            </TableCell>
                            <TableCell className="py-4">
                              <Badge variant="outline" className="text-[10px] h-5">
                                {log.type}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-[10px] font-semibold py-4">{log.user}</TableCell>
                            <TableCell className="text-xs py-4">{log.action}</TableCell>
                            <TableCell className="py-4">
                              <Badge
                                variant={log.result === "Success" ? "outline" : log.result === "Denied" ? "destructive" : "outline"}
                                className={`text-[10px] h-5 ${
                                  log.result === "Success"
                                    ? "border-success text-success"
                                    : log.result === "Denied"
                                      ? ""
                                      : "border-warning text-warning"
                                }`}
                              >
                                {log.result}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <ChevronRight
                                className={`w-4 h-4 text-muted-foreground transition-transform ${expandedRow === index ? "rotate-90" : ""}`}
                              />
                            </TableCell>
                          </TableRow>

                          {expandedRow === index && (
                            <TableRow className="border-border bg-slate-900/40 hover:bg-slate-900/40">
                              <TableCell colSpan={7} className="p-6">
                                <div className="grid md:grid-cols-3 gap-8 animate-in fade-in slide-in-from-top-2">
                                  <div className="space-y-4">
                                    <h4 className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
                                      Event Context
                                    </h4>
                                    <div className="space-y-2">
                                      {Object.keys(log.context || {}).length === 0 ? (
                                        <div className="text-[10px] text-muted-foreground">No context</div>
                                      ) : (
                                        <pre className="p-4 rounded-xl bg-slate-950 font-mono text-[10px] text-primary-foreground/80 overflow-auto max-h-32 border border-border/50">
                                          {JSON.stringify(log.context, null, 2)}
                                        </pre>
                                      )}
                                    </div>
                                  </div>

                                  <div className="md:col-span-2 space-y-4">
                                    <h4 className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
                                      Raw Data JSON
                                    </h4>
                                    <pre className="p-4 rounded-xl bg-slate-950 font-mono text-[10px] text-primary-foreground/80 overflow-auto max-h-32 border border-border/50">
                                      {JSON.stringify(log, null, 2)}
                                    </pre>
                                  </div>
                                </div>
                              </TableCell>
                            </TableRow>
                          )}
                        </React.Fragment>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </ScrollArea>
          </Card>
        </main>
      </div>
    </div>
  )
}
