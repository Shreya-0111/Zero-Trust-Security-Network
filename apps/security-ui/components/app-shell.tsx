"use client"

import Link from "next/link"
import { usePathname, useRouter } from "next/navigation"
import { useEffect, useMemo, useState } from "react"
import {
  Shield,
  Users,
  FileCheck,
  BookLock,
  Smartphone,
  LogOut,
  LayoutGrid,
  TimerReset,
  ShieldAlert,
  Activity,
} from "lucide-react"

import { useSession } from "@/hooks/use-session"
import { logout, HttpError } from "@/lib/api"
import { isRoleAllowed } from "@/lib/rbac"
import LoadingScreen from "@/components/loading-screen"

import {
  SidebarProvider,
  Sidebar,
  SidebarHeader,
  SidebarContent,
  SidebarFooter,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarInset,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

export default function AppShell(props: { children: React.ReactNode }) {
  const pathname = usePathname()
  const router = useRouter()
  const { loading, authenticated, user } = useSession() // Remove redirectToLogin option
  const [loggingOut, setLoggingOut] = useState(false)
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  const hideShell = pathname === "/login" || pathname === "/signup" || pathname.startsWith("/debug") || pathname.startsWith("/test")
  const role = user?.role

  // Remove the redirect logic from AppShell - let middleware handle it
  // useEffect(() => {
  //   if (!mounted || loading) return
  //   if (pathname === "/login" || pathname === "/signup" || pathname === "/debug-firebase") return
  //   if (!authenticated) {
  //     router.replace("/login")
  //   }
  // }, [authenticated, loading, pathname, router, mounted])

  const navItems = useMemo(() => {
    return [
      {
        title: "Dashboard",
        href: "/",
        icon: LayoutGrid,
        roles: ["admin", "faculty", "user"],
      },
      {
        title: "JIT Access",
        href: "/jit-access",
        icon: TimerReset,
        roles: ["admin", "faculty", "user"],
      },
      {
        title: "Emergency Access",
        href: "/emergency-access",
        icon: ShieldAlert,
        roles: ["admin", "faculty", "user"],
      },
      {
        title: "Security Monitoring",
        href: "/security-monitoring",
        icon: Activity,
        roles: ["admin"],
      },
      {
        title: "Visitor Registration",
        href: "/visitor-registration",
        icon: Users,
        roles: ["admin", "faculty"],
      },
      {
        title: "Visitor Tracking",
        href: "/visitor-tracking",
        icon: Shield,
        roles: ["admin"],
      },
      {
        title: "Device Management",
        href: "/device-management",
        icon: Smartphone,
        roles: ["admin", "faculty", "user"],
      },
      {
        title: "Audit Logs",
        href: "/audit-logs",
        icon: FileCheck,
        roles: ["admin"],
      },
      {
        title: "Policy Management",
        href: "/policy-management",
        icon: BookLock,
        roles: ["admin"],
      },
    ]
  }, [])

  const visibleNav = useMemo(() => {
    if (!mounted || !authenticated) return []
    return navItems.filter((x) => isRoleAllowed(role, x.roles))
  }, [authenticated, navItems, role, mounted])

  // Show loading state during hydration
  if (!mounted) {
    return <LoadingScreen />
  }

  if (hideShell) {
    return <>{props.children}</>
  }

  if (!loading && authenticated && role === "student") {
    return <>{props.children}</>
  }

  return (
    <SidebarProvider defaultOpen>
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <div className="flex items-center gap-2 px-2 py-1">
            <div className="p-2 rounded-lg bg-primary/10">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <div className="min-w-0">
              <div className="text-sm font-semibold truncate">Zero Trust</div>
              <div className="text-[10px] text-muted-foreground truncate">Security UI</div>
            </div>
          </div>
        </SidebarHeader>

        <SidebarContent>
          <SidebarMenu>
            {visibleNav.map((item) => {
              const Icon = item.icon
              const active = pathname === item.href
              return (
                <SidebarMenuItem key={item.href}>
                  <SidebarMenuButton asChild isActive={active} tooltip={item.title}>
                    <Link href={item.href}>
                      <Icon />
                      <span>{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              )
            })}
          </SidebarMenu>
        </SidebarContent>

        <SidebarFooter>
          <div className="px-2 py-2 text-[10px] text-muted-foreground truncate">
            {authenticated ? user?.email || user?.id : "Not signed in"}
          </div>
        </SidebarFooter>
      </Sidebar>

      <SidebarInset>
        <header className="h-14 border-b border-border bg-card/50 backdrop-blur-md flex items-center justify-between px-4 sticky top-0 z-40">
          <div className="flex items-center gap-2">
            <SidebarTrigger />
            <div className="text-sm font-medium truncate">{visibleNav.find((x) => x.href === pathname)?.title || ""}</div>
          </div>

          <div className="flex items-center gap-2">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" disabled={!authenticated || loggingOut}>
                  {authenticated ? (user?.role || "user") : "Guest"}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem
                  onSelect={async (e) => {
                    e.preventDefault()
                    if (!authenticated) {
                      router.replace("/login")
                      return
                    }
                    setLoggingOut(true)
                    try {
                      await logout()
                      router.replace("/login")
                    } catch (err) {
                      if (err instanceof HttpError) {
                        router.replace("/login")
                      } else {
                        router.replace("/login")
                      }
                    } finally {
                      setLoggingOut(false)
                    }
                  }}
                >
                  <LogOut className="mr-2 h-4 w-4" />
                  Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        <div className="min-h-[calc(100svh-3.5rem)]">{props.children}</div>
      </SidebarInset>
    </SidebarProvider>
  )
}
