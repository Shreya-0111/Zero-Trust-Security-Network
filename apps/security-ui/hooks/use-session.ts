"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { getSessionStatus, HttpError } from "@/lib/api"

type SessionUser = {
  id: string
  email?: string
  name?: string
  role?: string
}

export function useSession(options?: { redirectToLogin?: boolean }) {
  const router = useRouter()
  const [loading, setLoading] = useState(true)
  const [authenticated, setAuthenticated] = useState(false)
  const [user, setUser] = useState<SessionUser | null>(null)
  const [mounted, setMounted] = useState(false)
  const [hasRedirected, setHasRedirected] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  useEffect(() => {
    if (!mounted) return
    
    let cancelled = false

    async function run() {
      try {
        const res = await getSessionStatus()
        if (cancelled) return

        setAuthenticated(!!res.authenticated)
        setUser(res.user || null)

        // Only redirect if explicitly requested and we haven't redirected yet
        if (!res.authenticated && options?.redirectToLogin && !hasRedirected) {
          const currentPath = window.location.pathname
          // Don't redirect if already on public pages
          if (currentPath !== "/login" && currentPath !== "/signup" && !currentPath.startsWith("/debug") && !currentPath.startsWith("/test")) {
            setHasRedirected(true)
            router.replace("/login")
          }
        }
      } catch (err) {
        if (cancelled) return

        // Only redirect on 401 if we're not already on public pages and haven't redirected
        if (err instanceof HttpError && err.status === 401 && options?.redirectToLogin && !hasRedirected) {
          const currentPath = window.location.pathname
          if (currentPath !== "/login" && currentPath !== "/signup" && !currentPath.startsWith("/debug") && !currentPath.startsWith("/test")) {
            setHasRedirected(true)
            router.replace("/login")
          }
        }

        setAuthenticated(false)
        setUser(null)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    run()

    return () => {
      cancelled = true
    }
  }, [options?.redirectToLogin, router, mounted, hasRedirected])

  return { loading: loading || !mounted, authenticated, user }
}
