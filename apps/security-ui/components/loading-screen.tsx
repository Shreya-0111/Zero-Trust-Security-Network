"use client"

import { Shield, Loader2 } from "lucide-react"

export default function LoadingScreen() {
  return (
    <div className="min-h-screen bg-[#0f172a] flex items-center justify-center">
      <div className="text-center space-y-4">
        <div className="flex items-center justify-center mb-6">
          <div className="relative">
            <Shield className="w-16 h-16 text-blue-400" />
            <Loader2 className="w-6 h-6 text-white absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 animate-spin" />
          </div>
        </div>
        <h2 className="text-xl font-semibold text-white">Loading Security Framework</h2>
        <p className="text-gray-400">Initializing secure session...</p>
      </div>
    </div>
  )
}