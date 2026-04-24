"use client"

import Link from "next/link"
import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { useSession } from "@/hooks/use-session"
import { logout, HttpError } from "@/lib/api"
import { Shield, Smartphone, TimerReset, ShieldAlert, FileCheck, Lock } from "lucide-react"

export default function StudentHomePage() {
  const router = useRouter()
  const { loading, authenticated, user } = useSession({ redirectToLogin: true })
  const [error, setError] = useState<string | null>(null)
  const [isLoggingOut, setIsLoggingOut] = useState(false)

  useEffect(() => {
    if (loading) return
    if (!authenticated) return
    if (user?.role && user.role !== "student") {
      router.replace("/")
    }
  }, [authenticated, loading, router, user?.role])

  return (
    <div className="min-h-screen bg-background p-6 md:p-12">
      <div className="mx-auto max-w-5xl space-y-8">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Student Portal</h1>
            <p className="text-sm text-muted-foreground">Your account and security overview</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-base">Account</CardTitle>
              <CardDescription className="text-xs">Session details and actions</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="text-xs">
                <div className="text-muted-foreground">Signed in as</div>
                <div className="font-medium">{user?.email || user?.id || "student"}</div>
              </div>
              {error && <div className="text-xs text-destructive">{error}</div>}
              <div className="flex gap-2">
                <Button
                  className="flex-1"
                  disabled={isLoggingOut}
                  onClick={async () => {
                    setError(null)
                    setIsLoggingOut(true)
                    try {
                      await logout()
                      router.replace("/login")
                    } catch (e) {
                      setError(e instanceof HttpError ? e.message : "Logout failed")
                    } finally {
                      setIsLoggingOut(false)
                    }
                  }}
                >
                  {isLoggingOut ? "Signing out..." : "Sign out"}
                </Button>
                <Button asChild variant="outline" className="flex-1">
                  <Link href="/login?next=/student">Switch account</Link>
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-base">Available Modules</CardTitle>
              <CardDescription className="text-xs">Access is restricted for student role</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex items-center justify-between rounded-lg border border-border p-2">
                <div className="flex items-center gap-2">
                  <Smartphone className="w-4 h-4 text-muted-foreground" />
                  <div className="text-sm">Device Management</div>
                </div>
                <div className="flex items-center gap-1 text-muted-foreground text-xs">
                  <Lock className="w-3 h-3" />
                  Locked
                </div>
              </div>
              <div className="flex items-center justify-between rounded-lg border border-border p-2">
                <div className="flex items-center gap-2">
                  <TimerReset className="w-4 h-4 text-muted-foreground" />
                  <div className="text-sm">JIT Access</div>
                </div>
                <div className="flex items-center gap-1 text-muted-foreground text-xs">
                  <Lock className="w-3 h-3" />
                  Locked
                </div>
              </div>
              <div className="flex items-center justify-between rounded-lg border border-border p-2">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-muted-foreground" />
                  <div className="text-sm">Emergency Access</div>
                </div>
                <div className="flex items-center gap-1 text-muted-foreground text-xs">
                  <Lock className="w-3 h-3" />
                  Locked
                </div>
              </div>
              <div className="flex items-center justify-between rounded-lg border border-border p-2">
                <div className="flex items-center gap-2">
                  <FileCheck className="w-4 h-4 text-muted-foreground" />
                  <div className="text-sm">Audit Logs</div>
                </div>
                <div className="flex items-center gap-1 text-muted-foreground text-xs">
                  <Lock className="w-3 h-3" />
                  Locked
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-base">Help & Support</CardTitle>
              <CardDescription className="text-xs">Get assistance with access or security</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground">
                If you need access to a restricted module, contact your faculty or administrator.
              </p>
              <div className="flex gap-2">
                <Button asChild className="flex-1">
                  <a href="mailto:security-admin@example.com?subject=Access%20Request">Email admin</a>
                </Button>
                <Button asChild variant="outline" className="flex-1">
                  <Link href="/">Go to home</Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
