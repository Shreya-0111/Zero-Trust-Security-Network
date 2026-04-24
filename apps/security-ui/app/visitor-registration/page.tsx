"use client"

import React, { useState } from "react"
import { User, Building2, MapIcon, Camera, Upload, ArrowRight, ArrowLeft, QrCode, Clock, Search } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { registerVisitor, HttpError } from "@/lib/api"
import { useSession } from "@/hooks/use-session"
import AccessDenied from "@/components/access-denied"

export default function VisitorRegistrationPage() {
  const { loading: sessionLoading, authenticated, user } = useSession({ redirectToLogin: true })
  const [step, setStep] = useState(1)
  const [photo, setPhoto] = useState<string | null>(null)
  const [photoFile, setPhotoFile] = useState<File | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [successId, setSuccessId] = useState<string | null>(null)

  // Debug logging for photo state
  React.useEffect(() => {
    console.log("Photo state changed:", {
      photo: photo ? "URL set" : "No URL",
      photoFile: photoFile ? { name: photoFile.name, size: photoFile.size, type: photoFile.type } : "No file"
    })
  }, [photo, photoFile])

  const [fullName, setFullName] = useState("")
  const [phone, setPhone] = useState("")
  const [purpose, setPurpose] = useState("")
  const [expectedDuration, setExpectedDuration] = useState<string>("")
  const [hostName, setHostName] = useState("")
  const [hostId, setHostId] = useState("")
  const [hostDepartment, setHostDepartment] = useState("")

  if (!sessionLoading && authenticated && !(user?.role === "admin" || user?.role === "faculty")) {
    return <AccessDenied required={["admin", "faculty"]} />
  }

  const steps = [
    { id: 1, name: "Personal Info", icon: User },
    { id: 2, name: "Host Details", icon: Building2 },
    { id: 3, name: "Route & Pass", icon: MapIcon },
  ]

  const nextStep = () => setStep((s) => Math.min(s + 1, 3))
  const prevStep = () => setStep((s) => Math.max(s - 1, 1))

  const hours = Number(expectedDuration || 1)
  const validUntil = new Date(Date.now() + Math.max(1, Math.min(8, hours)) * 60 * 60 * 1000)
  const destination = hostDepartment || hostName || "Destination"

  return (
    <div className="min-h-screen bg-background p-6 md:p-12">
      <div className="max-w-4xl mx-auto space-y-8">
        {/* Progress Indicator */}
        <div className="flex items-center justify-between relative mb-12">
          <div className="absolute top-1/2 left-0 w-full h-1 bg-muted -translate-y-1/2 z-0" />
          <div
            className="absolute top-1/2 left-0 h-1 bg-accent -translate-y-1/2 z-0 transition-all duration-500"
            style={{ width: `${((step - 1) / (steps.length - 1)) * 100}%` }}
          />
          {steps.map((s) => {
            const Icon = s.icon
            const isActive = step >= s.id
            const isCurrent = step === s.id
            return (
              <div key={s.id} className="relative z-10 flex flex-col items-center">
                <div
                  className={`w-12 h-12 rounded-full flex items-center justify-center border-4 transition-all duration-500 ${
                    isCurrent
                      ? "bg-accent border-accent scale-110"
                      : isActive
                        ? "bg-accent border-accent"
                        : "bg-card border-muted"
                  }`}
                >
                  <Icon className={`w-5 h-5 ${isActive ? "text-white" : "text-muted-foreground"}`} />
                </div>
                <span
                  className={`mt-2 text-xs font-bold uppercase tracking-wider ${isActive ? "text-accent" : "text-muted-foreground"}`}
                >
                  {s.name}
                </span>
              </div>
            )
          })}
        </div>

        {/* Step Content */}
        <Card className="gradient-border overflow-hidden">
          <CardContent className="p-8">
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
              {step === 1 && (
                <div className="grid md:grid-cols-2 gap-12">
                  <div className="space-y-6">
                    <div className="space-y-2">
                      <h2 className="text-2xl font-bold">Personal Identification</h2>
                      <p className="text-muted-foreground">
                        Please provide your details and upload a photo for your visitor pass.
                      </p>
                    </div>

                    <div className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="name">Full Name</Label>
                        <Input id="name" placeholder="Johnathan Doe" className="bg-secondary/50" value={fullName} onChange={(e) => setFullName(e.target.value)} />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="phone">Phone Number</Label>
                        <Input id="phone" placeholder="+1 (555) 000-0000" className="bg-secondary/50" value={phone} onChange={(e) => setPhone(e.target.value)} />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="visit-purpose">Purpose (min 10 chars)</Label>
                        <Input id="visit-purpose" placeholder="Business meeting" className="bg-secondary/50" value={purpose} onChange={(e) => setPurpose(e.target.value)} />
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-col items-center justify-center gap-4">
                    <div className="w-64 h-64 rounded-2xl border-2 border-dashed border-muted flex flex-col items-center justify-center bg-card relative overflow-hidden group hover:border-accent transition-colors">
                      {photo ? (
                        <>
                          <img src={photo} alt="Preview" className="w-full h-full object-cover" />
                          <div className="absolute inset-0 bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                            <p className="text-white text-sm">Click to change photo</p>
                          </div>
                        </>
                      ) : (
                        <>
                          <div className="p-4 rounded-full bg-accent/10 mb-4 group-hover:scale-110 transition-transform">
                            <Camera className="w-8 h-8 text-accent" />
                          </div>
                          <p className="text-sm font-medium">Click to capture photo</p>
                          <p className="text-xs text-muted-foreground">or drag and drop</p>
                        </>
                      )}
                      <div className="absolute bottom-4 right-4">
                        <Button size="icon" variant="secondary" className="rounded-full shadow-lg">
                          <Upload className="w-4 h-4" />
                        </Button>
                      </div>
                      <input
                        type="file"
                        accept="image/*"
                        className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
                        onChange={(e) => {
                          const f = e.target.files?.[0]
                          if (!f) {
                            setPhotoFile(null)
                            setPhoto(null)
                            console.log("No file selected")
                            return
                          }
                          
                          console.log("File selected:", f.name, f.size, f.type)
                          
                          // Validate file type
                          const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif']
                          if (!allowedTypes.includes(f.type)) {
                            setError("Please select a valid image file (JPEG, PNG, or GIF)")
                            setPhotoFile(null)
                            setPhoto(null)
                            return
                          }
                          
                          // Validate file size (max 5MB)
                          if (f.size > 5 * 1024 * 1024) {
                            setError("Photo file size must be less than 5MB")
                            setPhotoFile(null)
                            setPhoto(null)
                            return
                          }
                          
                          // Clear any previous errors
                          setError(null)
                          
                          // Set the photo file and preview
                          setPhotoFile(f)
                          const previewUrl = URL.createObjectURL(f)
                          setPhoto(previewUrl)
                          
                          console.log("Photo successfully selected:", {
                            name: f.name,
                            size: f.size,
                            type: f.type,
                            previewUrl
                          })
                        }}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Photo will be used for AI facial verification at checkpoints.
                      {photoFile && (
                        <span className="block mt-1 text-green-600 font-medium">
                          ✓ Photo selected: {photoFile.name} ({(photoFile.size / 1024 / 1024).toFixed(2)} MB)
                        </span>
                      )}
                      {process.env.NODE_ENV === 'development' && (
                        <button
                          type="button"
                          onClick={() => {
                            console.log("Photo debug info:", {
                              photo,
                              photoFile: photoFile ? {
                                name: photoFile.name,
                                size: photoFile.size,
                                type: photoFile.type,
                                lastModified: photoFile.lastModified
                              } : null
                            })
                            alert(`Photo: ${photoFile ? 'Selected' : 'Not selected'}`)
                          }}
                          className="block mt-1 text-xs bg-blue-500 text-white px-2 py-1 rounded"
                        >
                          Debug Photo State
                        </button>
                      )}
                    </p>
                    
                    {/* Alternative photo selection button */}
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="mt-2"
                      onClick={() => {
                        const input = document.createElement('input')
                        input.type = 'file'
                        input.accept = 'image/*'
                        input.onchange = (e) => {
                          const f = (e.target as HTMLInputElement).files?.[0]
                          if (!f) {
                            setPhotoFile(null)
                            setPhoto(null)
                            console.log("No file selected")
                            return
                          }
                          
                          console.log("File selected via button:", f.name, f.size, f.type)
                          
                          // Validate file type
                          const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif']
                          if (!allowedTypes.includes(f.type)) {
                            setError("Please select a valid image file (JPEG, PNG, or GIF)")
                            setPhotoFile(null)
                            setPhoto(null)
                            return
                          }
                          
                          // Validate file size (max 5MB)
                          if (f.size > 5 * 1024 * 1024) {
                            setError("Photo file size must be less than 5MB")
                            setPhotoFile(null)
                            setPhoto(null)
                            return
                          }
                          
                          // Clear any previous errors
                          setError(null)
                          
                          // Set the photo file and preview
                          setPhotoFile(f)
                          const previewUrl = URL.createObjectURL(f)
                          setPhoto(previewUrl)
                          
                          console.log("Photo successfully selected via button:", {
                            name: f.name,
                            size: f.size,
                            type: f.type,
                            previewUrl
                          })
                        }
                        input.click()
                      }}
                    >
                      <Upload className="w-4 h-4 mr-2" />
                      {photoFile ? 'Change Photo' : 'Select Photo'}
                    </Button>
                  </div>
                </div>
              )}

              {step === 2 && (
                <div className="space-y-8 max-w-2xl mx-auto">
                  <div className="text-center space-y-2">
                    <h2 className="text-2xl font-bold">Host & Purpose</h2>
                    <p className="text-muted-foreground">Specify who you are visiting and the reason for your visit.</p>
                  </div>

                  <div className="grid gap-6">
                    <div className="space-y-2 relative">
                      <Label>Search Host</Label>
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input placeholder="Enter host name or department..." className="pl-10 bg-secondary/50" value={hostName} onChange={(e) => setHostName(e.target.value)} />
                      </div>
                    </div>

                    <div className="grid md:grid-cols-2 gap-6">
                      <div className="space-y-2">
                        <Label>Purpose of Visit</Label>
                        <Select value={purpose} onValueChange={setPurpose}>
                          <SelectTrigger className="bg-secondary/50">
                            <SelectValue placeholder="Select purpose" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="Business meeting">Business Meeting</SelectItem>
                            <SelectItem value="Maintenance/service">Maintenance/Service</SelectItem>
                            <SelectItem value="Delivery dropoff">Delivery</SelectItem>
                            <SelectItem value="Interview visit">Interview</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label>Expected Duration</Label>
                        <Select value={expectedDuration} onValueChange={setExpectedDuration}>
                          <SelectTrigger className="bg-secondary/50">
                            <SelectValue placeholder="Select duration" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="1">1 Hour</SelectItem>
                            <SelectItem value="2">2 Hours</SelectItem>
                            <SelectItem value="4">4 Hours</SelectItem>
                            <SelectItem value="8">8 Hours</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {step === 3 && (
                <div className="grid md:grid-cols-2 gap-12">
                  <div className="space-y-6">
                    <div className="space-y-2">
                      <h2 className="text-2xl font-bold">Assigned Route</h2>
                      <p className="text-muted-foreground">
                        Follow the assigned path to reach your destination. Any deviation will trigger an alert.
                      </p>
                    </div>

                    <div className="relative aspect-video rounded-xl bg-slate-900 overflow-hidden border border-border">
                      <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:20px_20px]" />
                      <svg className="absolute inset-0 w-full h-full" viewBox="0 0 400 200">
                        <path
                          d="M 50 150 L 150 150 L 150 50 L 300 50"
                          fill="none"
                          stroke="var(--color-accent)"
                          strokeWidth="4"
                          strokeDasharray="10 5"
                          className="animate-[dash_10s_linear_infinite]"
                        />
                        <circle cx="50" cy="150" r="6" fill="var(--color-accent)" className="pulse-glow" />
                        <circle cx="300" cy="50" r="6" fill="var(--color-accent)" />
                        <text x="60" y="165" fill="white" fontSize="10" fontWeight="bold">
                          ENTRY
                        </text>
                        <text x="310" y="55" fill="white" fontSize="10" fontWeight="bold">
                          {destination}
                        </text>
                      </svg>
                    </div>

                    <div className="flex items-center gap-4 p-4 rounded-xl bg-accent/10 border border-accent/20">
                      <Clock className="w-8 h-8 text-accent" />
                      <div>
                        <p className="text-xs uppercase font-bold text-accent">Valid For</p>
                        <p className="text-xl font-mono font-bold">{Math.max(1, Math.min(8, hours))} HOUR(S)</p>
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-col items-center justify-center gap-6 p-8 rounded-2xl bg-card border border-border shadow-2xl">
                    <div className="text-center">
                      <Badge variant="outline" className="mb-2 text-accent border-accent">
                        VISITOR PASS
                      </Badge>
                      <h3 className="text-xl font-bold">{fullName || "-"}</h3>
                      <p className="text-xs text-muted-foreground font-mono">ID: {successId || "PENDING"}</p>
                    </div>

                    <div className="p-4 bg-white rounded-xl shadow-inner">
                      <QrCode className="w-32 h-32 text-slate-900" />
                    </div>

                    <div className="space-y-2 w-full">
                      <div className="flex justify-between text-xs border-b border-border py-2">
                        <span className="text-muted-foreground">DESTINATION</span>
                        <span className="font-bold">{destination}</span>
                      </div>
                      <div className="flex justify-between text-xs border-b border-border py-2">
                        <span className="text-muted-foreground">VALID UNTIL</span>
                        <span className="font-bold">{validUntil.toLocaleString()}</span>
                      </div>
                    </div>

                    <Button className="w-full bg-accent hover:bg-accent/90">DOWNLOAD PASS</Button>
                  </div>
                </div>
              )}
            </div>
          </CardContent>

          <div className="p-6 border-t border-border bg-secondary/20 flex justify-between">
            <Button variant="ghost" onClick={prevStep} disabled={step === 1} className="gap-2">
              <ArrowLeft className="w-4 h-4" /> Back
            </Button>
            <Button
              onClick={async () => {
                if (step !== 3) {
                  nextStep()
                  return
                }

                setError(null)
                
                console.log("Starting visitor registration submission...")
                console.log("Current state:", {
                  photoFile: photoFile ? { name: photoFile.name, size: photoFile.size, type: photoFile.type } : null,
                  fullName: fullName.trim(),
                  phone: phone.trim(),
                  purpose: purpose.trim(),
                  expectedDuration,
                  user: user ? { id: user.id, role: user.role, name: user.name } : null
                })
                
                // Validate required fields with detailed error messages
                if (!photoFile) {
                  const errorMsg = "Photo is required - please select an image file by clicking the photo area above"
                  console.error("Validation failed:", errorMsg)
                  setError(errorMsg)
                  setStep(1) // Go back to photo step
                  return
                }
                if (fullName.trim().length < 1) {
                  const errorMsg = "Full name is required"
                  console.error("Validation failed:", errorMsg)
                  setError(errorMsg)
                  setStep(1)
                  return
                }
                if (phone.trim().length < 3) {
                  const errorMsg = "Phone number is required (minimum 3 characters)"
                  console.error("Validation failed:", errorMsg)
                  setError(errorMsg)
                  setStep(1)
                  return
                }
                if (purpose.trim().length < 10) {
                  const errorMsg = "Purpose must be at least 10 characters"
                  console.error("Validation failed:", errorMsg)
                  setError(errorMsg)
                  setStep(2)
                  return
                }
                if (!expectedDuration) {
                  const errorMsg = "Expected duration is required"
                  console.error("Validation failed:", errorMsg)
                  setError(errorMsg)
                  setStep(2)
                  return
                }

                const hours = Number(expectedDuration || 1)
                const visitorData = {
                  name: fullName,
                  phone,
                  visit_purpose: purpose,
                  expected_duration: Math.max(1, Math.min(8, hours)),
                  assigned_route: {
                    allowed_segments: [],
                    restricted_areas: [],
                    route_description: `Route to ${hostDepartment || hostName || "destination"}`,
                  },
                  host_id: hostId || (user?.id || ""),
                  host_name: hostName || (user?.name || ""),
                  host_department: hostDepartment || "",
                }

                console.log("Preparing form data for submission...")
                console.log("Visitor data:", visitorData)

                const fd = new FormData()
                fd.append("visitorData", JSON.stringify(visitorData))
                fd.append("photo", photoFile)

                console.log("FormData prepared:", {
                  visitorDataSize: JSON.stringify(visitorData).length,
                  photoFile: { name: photoFile.name, size: photoFile.size, type: photoFile.type }
                })

                setSubmitting(true)
                try {
                  console.log("Sending registration request...")
                  const res = await registerVisitor(fd)
                  console.log("Registration successful:", res)
                  const id = res?.visitor?.visitorId || res?.visitor?.visitor_id || res?.visitor?.id
                  setSuccessId(id || "REGISTERED")
                  setError(null)
                } catch (e) {
                  console.error("Registration failed:", e)
                  let errorMessage = "Failed to register visitor"
                  
                  if (e instanceof HttpError) {
                    errorMessage = e.message
                    
                    // Handle specific error cases
                    if (e.status === 401) {
                      errorMessage = "Authentication required. Please log in again."
                    } else if (e.status === 403) {
                      errorMessage = "Access denied. Only faculty and administrators can register visitors."
                    } else if (e.status === 400) {
                      // Check if it's a photo-related error
                      if (e.message.includes("photo") || e.message.includes("Photo")) {
                        errorMessage = `Photo upload error: ${e.message}`
                        setStep(1) // Go back to photo step
                      } else {
                        errorMessage = `Validation error: ${e.message}`
                      }
                    }
                  }
                  
                  setError(errorMessage)
                } finally {
                  setSubmitting(false)
                }
              }}
              className="bg-accent hover:bg-accent/90 gap-2"
              disabled={submitting}
            >
              {submitting ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Registering...
                </>
              ) : step === 3 ? (
                <>
                  Complete Registration
                  <ArrowRight className="w-4 h-4" />
                </>
              ) : (
                <>
                  Continue
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </Button>
          </div>
        </Card>

        {error && (
          <div className="text-xs text-destructive border border-destructive/30 bg-destructive/10 rounded-md p-3">
            <div className="font-medium mb-1">Registration Error:</div>
            <div>{error}</div>
            {process.env.NODE_ENV === 'development' && (
              <details className="mt-2">
                <summary className="cursor-pointer text-xs opacity-70">Debug Info</summary>
                <div className="mt-1 text-xs opacity-70 font-mono">
                  <div>User: {user ? `${user.name} (${user.role})` : 'Not authenticated'}</div>
                  <div>Photo: {photoFile ? `${photoFile.name} (${photoFile.size} bytes)` : 'No photo selected'}</div>
                  <div>Form Data: {JSON.stringify({ fullName, phone, purpose, expectedDuration }, null, 2)}</div>
                </div>
              </details>
            )}
          </div>
        )}

        {successId && (
          <div className="text-xs text-success border border-success/30 bg-success/10 rounded-md p-3">
            Visitor registered: {successId}
          </div>
        )}
      </div>

      <style jsx global>{`
        @keyframes dash {
          to { stroke-dashoffset: -100; }
        }
      `}</style>
    </div>
  )
}
