"use client"

import { useEffect, useMemo, useState } from "react"
import {
  Laptop,
  Smartphone,
  Tablet,
  MoreVertical,
  Plus,
  Clock,
  ChevronRight,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { ScrollArea } from "@/components/ui/scroll-area"
import { listUserDevices, registerDevice, removeDevice, HttpError } from "@/lib/api"
import { useSession } from "@/hooks/use-session"

export default function DeviceManagementPage() {
  const { loading: sessionLoading, authenticated, user } = useSession({ redirectToLogin: true })
  const [showAddModal, setShowAddModal] = useState(false)
  const [selectedDevice, setSelectedDevice] = useState<any>(null)
  const [registering, setRegistering] = useState(false)
  const [deviceName, setDeviceName] = useState("")

  const [devicesRaw, setDevicesRaw] = useState<any[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (sessionLoading || !authenticated) return
    const userId = user?.id
    if (!userId) return
    const uid: string = userId

    let cancelled = false
    async function run() {
      setIsLoading(true)
      setError(null)
      try {
        const res = await listUserDevices(uid)
        if (cancelled) return
        setDevicesRaw(res.devices || [])
      } catch (e) {
        if (cancelled) return
        setError(e instanceof HttpError ? e.message : "Failed to load devices")
      } finally {
        if (!cancelled) setIsLoading(false)
      }
    }

    run()
    return () => {
      cancelled = true
    }
  }, [authenticated, sessionLoading, user?.id])

  const devices = useMemo(() => {
    return (devicesRaw || []).map((d: any) => {
      const trust = Number(d.trustScore ?? 0)
      const status = trust >= 80 ? "Trusted" : trust >= 50 ? "Pending" : "Suspicious"
      return {
        id: d.deviceId || d.id,
        name: d.deviceName || "Device",
        type: "laptop",
        os: "",
        trustScore: trust,
        lastVerified: d.lastVerified || d.registeredAt || "",
        status,
      }
    })
  }, [devicesRaw])

  const selectedDeviceRaw = useMemo(() => {
    if (!selectedDevice?.id) return null
    return (devicesRaw || []).find((d: any) => (d.deviceId || d.id) === selectedDevice.id) || null
  }, [devicesRaw, selectedDevice?.id])

  const selectedDeviceLabel = useMemo(() => {
    return selectedDeviceRaw?.deviceName || selectedDevice?.name || "Device"
  }, [selectedDevice?.name, selectedDeviceRaw?.deviceName])

  const selectedDeviceTrust = useMemo(() => {
    const v = selectedDeviceRaw?.trustScore ?? selectedDevice?.trustScore ?? 0
    return Number(v) || 0
  }, [selectedDevice?.trustScore, selectedDeviceRaw?.trustScore])

  const handleRemove = async (deviceId: string) => {
    setError(null)
    try {
      await removeDevice(deviceId)
      setDevicesRaw((prev) => prev.filter((d: any) => (d.deviceId || d.id) !== deviceId))
      if (selectedDevice?.id === deviceId) setSelectedDevice(null)
    } catch (e) {
      setError(e instanceof HttpError ? e.message : "Failed to remove device")
    }
  }

  return (
    <div className="min-h-screen bg-background p-6 md:p-12 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Smartphone className="w-8 h-8 text-success" />
            Device Inventory
          </h1>
          <p className="text-muted-foreground">Manage and verify device trust for zero-trust access.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {/* Add New Device Card */}
        <Card
          className="border-2 border-dashed border-border bg-card/30 hover:bg-success/5 hover:border-success/50 transition-all cursor-pointer group flex flex-col items-center justify-center p-8 gap-4"
          onClick={() => {
            setShowAddModal(true)
          }}
        >
          <div className="w-16 h-16 rounded-full bg-success/10 flex items-center justify-center group-hover:scale-110 transition-transform">
            <Plus className="w-8 h-8 text-success" />
          </div>
          <div className="text-center">
            <h3 className="font-bold">Register New Device</h3>
            <p className="text-xs text-muted-foreground">Register this device for session trust</p>
          </div>
        </Card>

        {/* Device Cards */}
        {error && (
          <div className="col-span-full text-xs text-destructive border border-destructive/30 bg-destructive/10 rounded-md p-3">
            {error}
          </div>
        )}
        {isLoading && <div className="col-span-full text-xs text-muted-foreground">Loading devices...</div>}
        {devices.map((device) => {
          const Icon = device.type === "laptop" ? Laptop : device.type === "phone" ? Smartphone : Tablet
          return (
            <Card
              key={device.id}
              className="glass-card hover:shadow-xl hover:-translate-y-1 transition-all cursor-pointer group"
              onClick={() => setSelectedDevice(device)}
            >
              <CardContent className="p-6">
                <div className="flex items-start justify-between mb-6">
                  <div
                    className={`p-3 rounded-2xl ${
                      device.status === "Suspicious"
                        ? "bg-destructive/10 text-destructive"
                        : device.status === "Pending"
                          ? "bg-warning/10 text-warning"
                          : "bg-success/10 text-success"
                    }`}
                  >
                    <Icon className="w-6 h-6" />
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-muted-foreground hover:text-foreground"
                      >
                        <MoreVertical className="w-4 h-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="bg-slate-900 border-border">
                      <DropdownMenuItem className="text-xs">Verify Now</DropdownMenuItem>
                      <DropdownMenuItem className="text-xs">Device Details</DropdownMenuItem>
                      <DropdownMenuItem className="text-xs text-destructive" onClick={() => handleRemove(device.id)}>
                        Remove Device
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>

                <div className="space-y-4">
                  <div>
                    <h3 className="font-bold text-lg group-hover:text-success transition-colors">{device.name}</h3>
                    <p className="text-xs text-muted-foreground">{device.os}</p>
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="flex flex-col">
                      <span className="text-[10px] text-muted-foreground uppercase font-bold tracking-wider">
                        Trust Score
                      </span>
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-xl font-bold ${
                            device.trustScore > 80
                              ? "text-success"
                              : device.trustScore > 50
                                ? "text-warning"
                                : "text-destructive"
                          }`}
                        >
                          {device.trustScore}
                        </span>
                        <div className="w-16 h-1.5 bg-secondary rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              device.trustScore > 80
                                ? "bg-success"
                                : device.trustScore > 50
                                  ? "bg-warning"
                                  : "bg-destructive"
                            }`}
                            style={{ width: `${device.trustScore}%` }}
                          />
                        </div>
                      </div>
                    </div>
                    <Badge
                      variant={
                        device.status === "Suspicious"
                          ? "destructive"
                          : device.status === "Pending"
                            ? "outline"
                            : "outline"
                      }
                      className={`text-[10px] ${
                        device.status === "Trusted"
                          ? "border-success text-success bg-success/5"
                          : device.status === "Pending"
                            ? "border-warning text-warning bg-warning/5"
                            : ""
                      }`}
                    >
                      {device.status}
                    </Badge>
                  </div>

                  <div className="flex items-center gap-2 text-[10px] text-muted-foreground pt-2 border-t border-border/50">
                    <Clock className="w-3 h-3" />
                    Last Verified: {device.lastVerified}
                  </div>
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      {/* Device Details Sidebar/Panel (if selected) */}
      {selectedDevice && (
        <div className="fixed inset-y-0 right-0 w-full md:w-[450px] bg-card border-l border-border z-[60] shadow-2xl animate-in slide-in-from-right duration-300">
          <ScrollArea className="h-full">
            <div className="p-8 space-y-8">
              <div className="flex items-center justify-between">
                <Button variant="ghost" size="icon" onClick={() => setSelectedDevice(null)}>
                  <ChevronRight className="w-5 h-5 rotate-180" />
                </Button>
                <Badge className="bg-success/20 text-success border-success/50">DEVICE</Badge>
              </div>

              <div className="flex flex-col items-center gap-4 text-center">
                <div className="w-20 h-20 rounded-3xl bg-secondary flex items-center justify-center text-muted-foreground">
                  {selectedDevice.type === "laptop" ? (
                    <Laptop className="w-10 h-10" />
                  ) : (
                    <Smartphone className="w-10 h-10" />
                  )}
                </div>
                <div>
                  <h2 className="text-2xl font-bold">{selectedDeviceLabel}</h2>
                  <p className="text-muted-foreground text-sm font-mono">ID: {selectedDevice.id}</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <Card className="bg-secondary/30 border-border p-4">
                  <p className="text-[10px] text-muted-foreground uppercase font-bold mb-1">Trust Score</p>
                  <p className="text-2xl font-bold text-success">{selectedDeviceTrust}/100</p>
                </Card>
                <Card className="bg-secondary/30 border-border p-4">
                  <p className="text-[10px] text-muted-foreground uppercase font-bold mb-1">Last Verified</p>
                  <p className="text-xs font-mono text-muted-foreground truncate">
                    {String(selectedDeviceRaw?.lastVerified || selectedDeviceRaw?.registeredAt || selectedDevice?.lastVerified || "-")}
                  </p>
                </Card>
              </div>

              <section className="space-y-4">
                <h3 className="text-sm font-bold flex items-center gap-2">Device Metadata</h3>
                <div className="bg-slate-950 rounded-xl p-4 font-mono text-xs space-y-3 overflow-hidden">
                  <div className="flex justify-between items-center pb-2 border-b border-white/5">
                    <span className="text-slate-500">HASH</span>
                    <span className="text-success truncate ml-4">{String(selectedDevice.id).slice(0, 10)}...</span>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-slate-500">NAME</span>
                      <span className="text-slate-300">{selectedDeviceLabel}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">TRUST</span>
                      <span className="text-slate-300">{selectedDeviceTrust}/100</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">LAST VERIFIED</span>
                      <span className="text-slate-300 truncate ml-4">
                        {String(selectedDeviceRaw?.lastVerified || selectedDeviceRaw?.registeredAt || selectedDevice?.lastVerified || "-")}
                      </span>
                    </div>
                  </div>
                </div>
              </section>

              <Button className="w-full bg-destructive/10 text-destructive border border-destructive/20 hover:bg-destructive hover:text-white transition-all">
                REVOKE TRUST
              </Button>
            </div>
          </ScrollArea>
        </div>
      )}

      {/* Register Device Modal */}
      <Dialog open={showAddModal} onOpenChange={setShowAddModal}>
        <DialogContent className="sm:max-w-md bg-card border-border">
          <DialogHeader>
            <DialogTitle>Register Device</DialogTitle>
            <DialogDescription>Name this device and register it for session trust scoring.</DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <p className="text-xs text-muted-foreground">Device Name (optional)</p>
              <Input
                value={deviceName}
                onChange={(e) => setDeviceName(e.target.value)}
                placeholder="e.g. Aditya's MacBook"
                className="bg-secondary/50 border-border"
              />
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddModal(false)}>
              Cancel
            </Button>
            <Button
              disabled={registering || sessionLoading || !authenticated || !user?.id}
              className="bg-success hover:bg-success/90"
              onClick={async () => {
                if (!user?.id) return
                setError(null)
                setRegistering(true)
                try {
                  // Collect comprehensive device fingerprint
                  const getFingerprint = () => {
                    if (typeof window === "undefined") return {}

                    // Canvas fingerprint
                    let canvasHash = ""
                    try {
                      const canvas = document.createElement("canvas")
                      const ctx = canvas.getContext("2d")
                      if (ctx) {
                        ctx.textBaseline = "top"
                        ctx.font = "14px 'Arial'"
                        ctx.textBaseline = "alphabetic"
                        ctx.fillStyle = "#f60"
                        ctx.fillRect(125, 1, 62, 20)
                        ctx.fillStyle = "#069"
                        ctx.fillText("shh_fingerprint_v1", 2, 15)
                        ctx.fillStyle = "rgba(102, 204, 0, 0.7)"
                        ctx.fillText("shh_fingerprint_v1", 4, 17)
                        canvasHash = canvas.toDataURL().slice(-50) // Use part of data URL as hash
                      }
                    } catch (e) {
                      console.warn("Canvas fingerprint failed", e)
                    }

                    // WebGL fingerprint
                    let webglInfo = { renderer: "unknown", vendor: "unknown", version: "unknown" }
                    try {
                      const canvas = document.createElement("canvas")
                      const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl")
                      if (gl) {
                        // @ts-ignore
                        const debugInfo = gl.getExtension("WEBGL_debug_renderer_info")
                        if (debugInfo) {
                          // @ts-ignore
                          webglInfo.renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
                          // @ts-ignore
                          webglInfo.vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)
                        }
                        // @ts-ignore
                        webglInfo.version = gl.getParameter(gl.VERSION)
                      }
                    } catch (e) {
                      console.warn("WebGL fingerprint failed", e)
                    }

                    return {
                      userAgent: navigator.userAgent,
                      platform: navigator.platform,
                      language: navigator.language,
                      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                      screen: {
                        width: window.screen.width,
                        height: window.screen.height,
                        colorDepth: window.screen.colorDepth,
                        pixelRatio: window.devicePixelRatio,
                      },
                      canvas: {
                        hash: canvasHash || "fallback_hash",
                        confidence: 100,
                      },
                      webgl: webglInfo,
                      audio: {
                        hash: "audio_hash_placeholder", // Placeholder as real audio fingerprinting is complex
                        sampleRate: 44100,
                        bufferSize: 1024,
                      },
                      system: {
                        platform: navigator.platform,
                        language: navigator.language,
                        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                        hardwareConcurrency: navigator.hardwareConcurrency || 4,
                        userAgent: navigator.userAgent,
                      },
                      registeredAt: new Date().toISOString(),
                    }
                  }

                  const fp = getFingerprint()
                  await registerDevice({
                    userId: user.id,
                    deviceName: deviceName || undefined,
                    fingerprintData: fp,
                    mfaVerified: false,
                  })
                  const res = await listUserDevices(user.id)
                  setDevicesRaw(res.devices || [])
                  setShowAddModal(false)
                  setDeviceName("")
                } catch (e) {
                  setError(e instanceof HttpError ? e.message : "Failed to register device")
                } finally {
                  setRegistering(false)
                }
              }}
            >
              {registering ? "Registering..." : "Complete Registration"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
