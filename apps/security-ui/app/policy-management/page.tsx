"use client"

import { DropdownMenuItem } from "@/components/ui/dropdown-menu"

import { DropdownMenuContent } from "@/components/ui/dropdown-menu"

import { DropdownMenuTrigger } from "@/components/ui/dropdown-menu"

import { DropdownMenu } from "@/components/ui/dropdown-menu"

import { useEffect, useMemo, useState } from "react"
import {
  BookLock,
  Plus,
  Shield,
  Smartphone,
  Settings2,
  Trash2,
  Edit,
  Info,
  UserCheck,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Slider } from "@/components/ui/slider"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Checkbox } from "@/components/ui/checkbox"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ScrollArea } from "@/components/ui/scroll-area"
import { getPolicyRules, upsertPolicy, deletePolicy, HttpError } from "@/lib/api"
import { useSession } from "@/hooks/use-session"
import AccessDenied from "@/components/access-denied"

export default function PolicyManagementPage() {
  const { loading: sessionLoading, authenticated, user } = useSession({ redirectToLogin: true })
  const [showEditor, setShowEditor] = useState(false)
  const [confidenceThreshold, setConfidenceThreshold] = useState([75])

  const [newPolicyName, setNewPolicyName] = useState("")
  const [newPolicyDescription, setNewPolicyDescription] = useState("")
  const [newPolicyPriority, setNewPolicyPriority] = useState([4])
  const [newAllowedRoles, setNewAllowedRoles] = useState<string[]>(["admin"])
  const [saving, setSaving] = useState(false)

  const [policiesRaw, setPoliciesRaw] = useState<any[]>([])
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
        const res = await getPolicyRules(true)
        if (cancelled) return
        setPoliciesRaw(res.policies || [])
      } catch (e) {
        if (cancelled) return
        setError(e instanceof HttpError ? e.message : "Failed to load policies")
      } finally {
        if (!cancelled) setIsLoading(false)
      }
    }

    run()
    return () => {
      cancelled = true
    }
  }, [authenticated, sessionLoading, user?.role])

  const policies = useMemo(() => {
    return (policiesRaw || []).map((p: any) => {
      return {
        id: p.policyId || p.id,
        name: p.name || "Policy",
        desc: p.description || "",
        active: !!p.isActive,
        type: (p.rules && p.rules[0] && p.rules[0].resourceType) || "Policy",
        appliedCount: 0,
      }
    })
  }, [policiesRaw])

  async function refreshPolicies() {
    setIsLoading(true)
    setError(null)
    try {
      const res = await getPolicyRules(true)
      setPoliciesRaw(res.policies || [])
    } catch (e) {
      setError(e instanceof HttpError ? e.message : "Failed to load policies")
    } finally {
      setIsLoading(false)
    }
  }

  if (unauthorized) {
    return <AccessDenied required={["admin"]} />
  }

  return (
    <div className="min-h-screen bg-background p-6 md:p-12 space-y-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <BookLock className="w-8 h-8 text-[#7c3aed]" />
            Security Policies
          </h1>
          <p className="text-muted-foreground">Define and simulate zero-trust access rules and conditions.</p>
        </div>

        <div className="flex items-center gap-3">
          <Button className="bg-[#7c3aed] hover:bg-[#7c3aed]/90 gap-2" onClick={() => setShowEditor(true)}>
            <Plus className="w-4 h-4" /> Create Policy
          </Button>
        </div>
      </div>

      <div className="grid gap-8">
        <div className="space-y-6">
          <div className="flex items-center justify-between p-4 rounded-xl bg-card border border-border">
            <div className="flex gap-2">
              <Button size="sm" variant="secondary" className="text-xs">
                All Policies
              </Button>
            </div>
            <div className="relative w-64">
              <Input placeholder="Search policies..." className="h-8 pl-8 bg-secondary/50 text-xs" />
              <Shield className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            </div>
          </div>

          <div className="grid gap-4">
            {policies.map((policy) => (
              <Card key={policy.id} className="glass-card hover:border-[#7c3aed]/50 transition-all group">
                <CardContent className="p-6">
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-1 flex-1">
                      <div className="flex items-center gap-2">
                        <h3 className="font-bold group-hover:text-[#7c3aed] transition-colors">{policy.name}</h3>
                        <Badge variant="outline" className="text-[10px] h-4">
                          {policy.type}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground leading-relaxed">{policy.desc}</p>
                    </div>
                    <div className="flex items-center gap-4 shrink-0">
                      <div className="flex items-center gap-3">
                        <Switch
                          checked={policy.active}
                          onCheckedChange={async (v) => {
                            try {
                              await upsertPolicy({ policyId: policy.id, isActive: !!v })
                              await refreshPolicies()
                            } catch (e) {
                              setError(e instanceof HttpError ? e.message : "Failed to update policy")
                            }
                          }}
                        />
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-8 w-8">
                              <Settings2 className="w-4 h-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end" className="bg-slate-900">
                            <DropdownMenuItem
                              className="text-xs gap-2 text-destructive"
                              onSelect={async (e) => {
                                e.preventDefault()
                                try {
                                  await deletePolicy(policy.id)
                                  await refreshPolicies()
                                } catch (err) {
                                  setError(err instanceof HttpError ? err.message : "Failed to delete policy")
                                }
                              }}
                            >
                              <Trash2 className="w-3.5 h-3.5" /> Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </div>

      {/* Policy Editor Modal */}
      <Dialog open={showEditor} onOpenChange={setShowEditor}>
        <DialogContent className="max-w-3xl bg-slate-950 border-border p-0 overflow-hidden flex flex-col h-[600px]">
          <DialogHeader className="p-6 border-b border-border">
            <DialogTitle>Create Security Policy</DialogTitle>
            <DialogDescription>Configure dynamic access rules and context requirements.</DialogDescription>
          </DialogHeader>

          <Tabs defaultValue="basic" className="flex-1 flex flex-col overflow-hidden">
            <div className="px-6 border-b border-border bg-slate-900/50">
              <TabsList className="bg-transparent h-12 w-full justify-start gap-6 rounded-none p-0">
                <TabsTrigger
                  value="basic"
                  className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#7c3aed] data-[state=active]:bg-transparent data-[state=active]:shadow-none px-0"
                >
                  Basic Info
                </TabsTrigger>
                <TabsTrigger
                  value="rules"
                  className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#7c3aed] data-[state=active]:bg-transparent data-[state=active]:shadow-none px-0"
                >
                  Access Rules
                </TabsTrigger>
                <TabsTrigger
                  value="conditions"
                  className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#7c3aed] data-[state=active]:bg-transparent data-[state=active]:shadow-none px-0"
                >
                  Conditions
                </TabsTrigger>
              </TabsList>
            </div>

            <ScrollArea className="flex-1 p-6">
              <TabsContent value="basic" className="m-0 space-y-6">
                <div className="grid gap-4">
                  <div className="space-y-2">
                    <Label>Policy Name</Label>
                    <Input
                      placeholder="e.g. Critical DB Access Policy"
                      className="bg-slate-900 border-slate-800"
                      value={newPolicyName}
                      onChange={(e) => setNewPolicyName(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Description</Label>
                    <Textarea
                      placeholder="Explain the purpose and scope of this policy..."
                      className="bg-slate-900 border-slate-800 min-h-[100px]"
                      value={newPolicyDescription}
                      onChange={(e) => setNewPolicyDescription(e.target.value)}
                    />
                  </div>
                  <div className="space-y-4 pt-4">
                    <div className="flex justify-between">
                      <Label>Execution Priority</Label>
                      <span className="text-xs font-bold text-[#7c3aed]">LEVEL {newPolicyPriority[0]}</span>
                    </div>
                    <Slider value={newPolicyPriority} onValueChange={setNewPolicyPriority} max={10} step={1} />
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="rules" className="m-0 space-y-8">
                <div className="space-y-4">
                  <h4 className="text-sm font-bold flex items-center gap-2">
                    <UserCheck className="w-4 h-4 text-[#7c3aed]" />
                    Role-Based Access
                  </h4>
                  <div className="grid grid-cols-2 gap-3">
                    {["admin", "faculty", "student", "user"].map((role) => (
                      <div key={role} className="flex items-center gap-3 p-3 rounded-lg border border-border bg-card">
                        <Checkbox
                          id={role}
                          checked={newAllowedRoles.includes(role)}
                          onCheckedChange={(v) => {
                            const on = !!v
                            setNewAllowedRoles((prev) => {
                              if (on) return Array.from(new Set([...prev, role]))
                              return prev.filter((x) => x !== role)
                            })
                          }}
                        />
                        <label htmlFor={role} className="text-xs">
                          {role}
                        </label>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-6">
                  <div className="flex justify-between items-center">
                    <h4 className="text-sm font-bold flex items-center gap-2">
                      <Shield className="w-4 h-4 text-[#7c3aed]" />
                      Confidence Threshold
                    </h4>
                    <span className="text-lg font-bold text-[#7c3aed] font-mono">{confidenceThreshold[0]}%</span>
                  </div>
                  <Slider
                    value={confidenceThreshold}
                    onValueChange={setConfidenceThreshold}
                    max={100}
                    step={1}
                    className="py-2"
                  />
                  <div className="p-3 rounded-lg bg-[#7c3aed]/5 border border-[#7c3aed]/20 flex items-center gap-3">
                    <Info className="w-4 h-4 text-[#7c3aed]" />
                    <p className="text-[10px] text-muted-foreground">
                      Access requests with confidence scores below this threshold will trigger mandatory dual-approval.
                    </p>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="conditions" className="m-0 space-y-6">
                <div className="space-y-4">
                  <h4 className="text-sm font-bold flex items-center gap-2">
                    <Smartphone className="w-4 h-4 text-[#7c3aed]" />
                    Context Requirements
                  </h4>
                  <div className="space-y-2">
                    {[
                      "Authenticated Session Required",
                      "MFA Required for High-Risk Access",
                      "Role Must Match Policy",
                      "Confidence Score Threshold Met",
                    ].map((cond) => (
                      <div
                        key={cond}
                        className="flex items-center justify-between p-3 rounded-lg border border-border bg-card"
                      >
                        <span className="text-xs">{cond}</span>
                        <Switch />
                      </div>
                    ))}
                  </div>
                </div>
              </TabsContent>
            </ScrollArea>

            <DialogFooter className="p-6 border-t border-border bg-slate-900/50">
              <Button variant="ghost" onClick={() => setShowEditor(false)}>
                Cancel
              </Button>
              <Button
                className="bg-[#7c3aed] hover:bg-[#7c3aed]/90 px-8"
                disabled={saving}
                onClick={async () => {
                  setError(null)
                  if (!newPolicyName.trim()) {
                    setError("Policy name is required")
                    return
                  }
                  if (newAllowedRoles.length === 0) {
                    setError("Select at least one allowed role")
                    return
                  }
                  setSaving(true)
                  try {
                    await upsertPolicy({
                      name: newPolicyName.trim(),
                      description: newPolicyDescription.trim(),
                      priority: newPolicyPriority[0],
                      rules: [
                        {
                          resourceType: "resource_segment",
                          allowedRoles: newAllowedRoles,
                          minConfidence: confidenceThreshold[0],
                          mfaRequired: true,
                        },
                      ],
                    })
                    setShowEditor(false)
                    setNewPolicyName("")
                    setNewPolicyDescription("")
                    setNewPolicyPriority([4])
                    setNewAllowedRoles(["admin"])
                    await refreshPolicies()
                  } catch (e) {
                    setError(e instanceof HttpError ? e.message : "Failed to create policy")
                  } finally {
                    setSaving(false)
                  }
                }}
              >
                {saving ? "SAVING..." : "Create Policy"}
              </Button>
            </DialogFooter>
          </Tabs>
        </DialogContent>
      </Dialog>

      <style jsx global>{`
        /* Minimalist scrollbar for areas */
        .scrollbar-hide::-webkit-scrollbar { display: none; }
      `}</style>
    </div>
  )
}
