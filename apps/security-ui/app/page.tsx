"use client"

import Link from "next/link"
import { useEffect, useMemo } from "react"
import { useRouter } from "next/navigation"
import { Shield, Users, FileCheck, BookLock, Smartphone, MapIcon, TimerReset, ShieldAlert, Activity } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useSession } from "@/hooks/use-session"
import { isRoleAllowed } from "@/lib/rbac"

export default function HomePage() {
  const router = useRouter()
  const { loading, authenticated, user } = useSession()

  // Remove redundant redirect logic - let middleware handle authentication
  // useEffect(() => {
  //   if (!loading && !authenticated) {
  //     const currentPath = window.location.pathname
  //     if (currentPath !== "/login" && currentPath !== "/signup") {
  //       router.replace("/login")
  //     }
  //   }
  // }, [authenticated, loading, router])

  useEffect(() => {
    if (loading || !authenticated) return
    if (user?.role === "student") {
      router.replace("/student")
    }
  }, [authenticated, loading, router, user?.role])

  const modules = useMemo(
    () => [
      {
        title: 'Login',
        description: 'Zero Trust authentication with MFA and session management',
        icon: Shield,
        href: '/login',
        color: 'text-primary',
        bgColor: 'bg-primary/10'
      },
      {
        title: 'Visitor Registration',
        description: 'Multi-step visitor onboarding with route assignment',
        icon: Users,
        href: '/visitor-registration',
        color: 'text-accent',
        bgColor: 'bg-accent/10',
        roles: ['admin', 'faculty']
      },
      {
        title: 'JIT Access',
        description: 'Request temporary elevated access to protected resources',
        icon: TimerReset,
        href: '/jit-access',
        color: 'text-primary',
        bgColor: 'bg-primary/10',
        roles: ['admin', 'faculty', 'user']
      },
      {
        title: 'Emergency Access',
        description: 'Break-glass access requests with audit trail and approvals',
        icon: ShieldAlert,
        href: '/emergency-access',
        color: 'text-destructive',
        bgColor: 'bg-destructive/10',
        roles: ['admin', 'faculty', 'user']
      },
      {
        title: 'Security Monitoring',
        description: 'Operational health, metrics, and log summaries',
        icon: Activity,
        href: '/security-monitoring',
        color: 'text-muted-foreground',
        bgColor: 'bg-muted',
        roles: ['admin']
      },
      {
        title: 'Visitor Tracking',
        description: 'Live tracking and compliance monitoring for active visitors',
        icon: MapIcon,
        href: '/visitor-tracking',
        color: 'text-warning',
        bgColor: 'bg-warning/10',
        roles: ['admin']
      },
      {
        title: 'Device Management',
        description: 'Register and manage device trust for zero-trust access',
        icon: Smartphone,
        href: '/device-management',
        color: 'text-success',
        bgColor: 'bg-success/10',
        roles: ['admin', 'faculty', 'user']
      },
      {
        title: 'Audit Logs',
        description: 'Advanced event tracking and compliance reporting',
        icon: FileCheck,
        href: '/audit-logs',
        color: 'text-muted-foreground',
        bgColor: 'bg-muted',
        roles: ['admin']
      },
      {
        title: 'Policy Management',
        description: 'Configure security policies and access rules',
        icon: BookLock,
        href: '/policy-management',
        color: 'text-chart-3',
        bgColor: 'bg-chart-3/10',
        roles: ['admin']
      }
    ],
    []
  )

  const visibleModules = useMemo(() => {
    if (!authenticated) return []
    const role = user?.role
    return modules
      .filter((m: any) => m.href !== "/login")
      .filter((m: any) => {
        if (!m.roles) return true
        return isRoleAllowed(role, m.roles)
      })
  }, [authenticated, modules, user?.role])

  if (!authenticated) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-6">
        <div className="text-sm text-muted-foreground">Redirecting to login...</div>
      </div>
    )
  }

  if (user?.role === "student") {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-6">
        <div className="text-sm text-muted-foreground">Redirecting to student portal...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Shield className="w-8 h-8 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-balance">Zero Trust Security Framework</h1>
              <p className="text-sm text-muted-foreground">Comprehensive Access Control and Monitoring System</p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-12">
        <div className="mb-8">
          <h2 className="text-3xl font-bold mb-2 text-balance">Security Modules</h2>
          <p className="text-muted-foreground text-balance">Select a module to access its interface</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {visibleModules.map((module: any) => {
            const Icon = module.icon
            return (
              <Link key={module.href} href={module.href}>
                <Card className="h-full transition-all hover:shadow-lg hover:shadow-primary/20 hover:border-primary/50 hover:-translate-y-1 cursor-pointer group">
                  <CardHeader>
                    <div className={`w-12 h-12 rounded-lg ${module.bgColor} flex items-center justify-center mb-3 transition-transform group-hover:scale-110`}>
                      <Icon className={`w-6 h-6 ${module.color}`} />
                    </div>
                    <CardTitle className="text-balance">{module.title}</CardTitle>
                    <CardDescription className="text-balance">{module.description}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="text-sm text-primary font-medium group-hover:translate-x-1 transition-transform inline-flex items-center gap-1">
                      Open Module
                      <span className="text-lg">→</span>
                    </div>
                  </CardContent>
                </Card>
              </Link>
            )
          })}
        </div>

        {/* Footer Info */}
        <div className="mt-16 p-6 rounded-xl bg-card border border-border">
          <div className="flex items-start gap-4">
            <div className="p-2 rounded-lg bg-primary/10">
              <Shield className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h3 className="font-semibold mb-2 text-balance">About Zero Trust Security</h3>
              <p className="text-sm text-muted-foreground leading-relaxed text-pretty">
                This framework implements a comprehensive Zero Trust security model with continuous verification, 
                least-privilege access, device trust scoring, and real-time monitoring. All access requests are 
                evaluated against dynamic policies with confidence scoring before granting temporary, context-aware permissions.
              </p>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
