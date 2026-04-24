"use client"

import Link from "next/link"
import { ShieldAlert } from "lucide-react"
import { Button } from "@/components/ui/button"

export default function AccessDenied(props: { required?: string[] }) {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-6">
      <div className="max-w-md w-full border border-border rounded-xl bg-card p-6 space-y-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-destructive/10 text-destructive">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-lg font-bold">Access denied</h1>
            <p className="text-xs text-muted-foreground">You don’t have permission to view this page.</p>
          </div>
        </div>

        {props.required && props.required.length > 0 && (
          <p className="text-xs text-muted-foreground">Required role: {props.required.join(" or ")}</p>
        )}

        <div className="flex gap-2">
          <Button asChild className="flex-1">
            <Link href="/">Go home</Link>
          </Button>
          <Button asChild variant="outline" className="flex-1">
            <Link href="/login">Login</Link>
          </Button>
        </div>
      </div>
    </div>
  )
}
