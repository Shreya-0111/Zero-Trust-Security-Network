"use client"

import type React from "react"
import { useState, useEffect } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Shield, Lock, Mail, User, Building, GraduationCap, Loader2, ArrowRight, AlertCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { signupUser, HttpError } from "@/lib/api"
import { auth, firebaseConfigStatus } from "@/lib/firebase"
import { createUserWithEmailAndPassword } from "firebase/auth"
import { useSession } from "@/hooks/use-session"

export default function SignupClient() {
  const router = useRouter()
  const { loading: sessionLoading, authenticated, user } = useSession({ redirectToLogin: false })
  const [isLoading, setIsLoading] = useState(false)
  const [formData, setFormData] = useState({
    email: "",
    password: "",
    confirmPassword: "",
    name: "",
    role: "",
    department: "",
    studentId: ""
  })
  const [error, setError] = useState<string | null>(null)

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }))
  }

  const validateForm = () => {
    if (!formData.email || !formData.password || !formData.name || !formData.role) {
      setError("Please fill in all required fields")
      return false
    }

    if (formData.password !== formData.confirmPassword) {
      setError("Passwords do not match")
      return false
    }

    if (formData.password.length < 6) {
      setError("Password must be at least 6 characters long")
      return false
    }

    if (formData.role === "student" && !formData.studentId) {
      setError("Student ID is required for students")
      return false
    }

    return true
  }

  useEffect(() => {
    if (!sessionLoading && authenticated) {
      const role = user?.role
      if (role === "student") {
        router.replace("/student")
      } else {
        router.replace("/")
      }
    }
  }, [authenticated, sessionLoading, router, user?.role])

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    if (!validateForm()) {
      return
    }

    setIsLoading(true)
    try {
      if (!auth) {
        throw new Error(
          "Firebase is not configured. Set NEXT_PUBLIC_FIREBASE_* env vars in apps/security-ui/.env.local and restart the dev server."
        )
      }

      // Create user with Firebase Auth
      const cred = await createUserWithEmailAndPassword(auth, formData.email, formData.password)
      const idToken = await cred.user.getIdToken()

      // Register user with backend
      const signupData = {
        idToken,
        name: formData.name,
        role: formData.role,
        department: formData.department,
        studentId: formData.role === "student" ? formData.studentId : undefined
      }

      const res = await signupUser(signupData)
      
      // Redirect based on role
      const role = res.user?.role
      if (role === "student") {
        router.replace("/student")
      } else {
        router.replace("/")
      }
    } catch (err) {
      if (err instanceof HttpError) {
        setError(err.message)
      } else {
        setError(err instanceof Error ? err.message : "Signup failed")
      }
    } finally {
      setIsLoading(false)
    }
  }

  // Show Firebase configuration error if not properly set up
  if (!firebaseConfigStatus.hasRealConfig) {
    return (
      <div className="min-h-screen bg-[#0f172a] flex items-center justify-center p-8">
        <Card className="w-full max-w-md bg-white/10 backdrop-blur-md border-white/20">
          <CardContent className="p-8">
            <div className="text-center mb-6">
              <AlertCircle className="w-16 h-16 text-yellow-400 mx-auto mb-4" />
              <h1 className="text-2xl font-bold text-white mb-2">Firebase Configuration Required</h1>
              <p className="text-gray-300">Please set up your Firebase web app configuration</p>
            </div>
            
            <div className="space-y-4 text-sm text-gray-300">
              <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4">
                <h3 className="font-semibold text-yellow-400 mb-2">Steps to Fix:</h3>
                <ol className="list-decimal list-inside space-y-1">
                  <li>Go to Firebase Console</li>
                  <li>Get your web app configuration</li>
                  <li>Update apps/security-ui/.env.local</li>
                  <li>Restart the dev server</li>
                </ol>
              </div>
              
              <div className="text-center">
                <p className="text-gray-400">
                  See <code className="bg-gray-800 px-2 py-1 rounded">GET_FIREBASE_CONFIG.md</code> for detailed instructions
                </p>
                <Link href="/login" className="text-blue-400 hover:text-blue-300 mt-2 inline-block">
                  ← Back to Login
                </Link>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#0f172a] flex overflow-hidden">
      {/* Left Side: Animated Background & Security Icons */}
      <div className="hidden lg:flex lg:w-1/2 relative flex-col items-center justify-center p-12 overflow-hidden bg-[#0f172a]">
        {/* Animated gradient background */}
        <div className="absolute inset-0 bg-gradient-to-br from-blue-900/20 via-purple-900/20 to-cyan-900/20 animate-pulse" />
        
        {/* Floating security icons */}
        <div className="relative z-10 space-y-8">
          <div className="flex items-center space-x-4 animate-float">
            <Shield className="w-12 h-12 text-blue-400" />
            <div className="text-white">
              <h3 className="text-xl font-semibold">Zero Trust Security</h3>
              <p className="text-gray-300">Advanced protection for your data</p>
            </div>
          </div>
          
          <div className="flex items-center space-x-4 animate-float-delayed">
            <Lock className="w-12 h-12 text-purple-400" />
            <div className="text-white">
              <h3 className="text-xl font-semibold">Multi-Factor Authentication</h3>
              <p className="text-gray-300">Enhanced security layers</p>
            </div>
          </div>
          
          <div className="flex items-center space-x-4 animate-float">
            <GraduationCap className="w-12 h-12 text-cyan-400" />
            <div className="text-white">
              <h3 className="text-xl font-semibold">Academic Security</h3>
              <p className="text-gray-300">Tailored for educational institutions</p>
            </div>
          </div>
        </div>
      </div>

      {/* Right Side: Signup Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-8">
        <Card className="w-full max-w-md bg-white/10 backdrop-blur-md border-white/20">
          <CardContent className="p-8">
            <div className="text-center mb-8">
              <div className="flex items-center justify-center mb-4">
                <Shield className="w-12 h-12 text-blue-400" />
              </div>
              <h1 className="text-3xl font-bold text-white mb-2">Create Account</h1>
              <p className="text-gray-300">Join our secure platform</p>
            </div>

            <form onSubmit={handleSignup} className="space-y-6">
              {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
                  <p className="text-red-400 text-sm">{error}</p>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="name" className="text-white">Full Name *</Label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <Input
                    id="name"
                    type="text"
                    value={formData.name}
                    onChange={(e) => handleInputChange("name", e.target.value)}
                    className="pl-10 bg-white/5 border-white/20 text-white placeholder-gray-400"
                    placeholder="Enter your full name"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="email" className="text-white">Email Address *</Label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <Input
                    id="email"
                    type="email"
                    value={formData.email}
                    onChange={(e) => handleInputChange("email", e.target.value)}
                    className="pl-10 bg-white/5 border-white/20 text-white placeholder-gray-400"
                    placeholder="Enter your email"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="role" className="text-white">Role *</Label>
                <Select value={formData.role} onValueChange={(value) => handleInputChange("role", value)}>
                  <SelectTrigger className="bg-white/5 border-white/20 text-white">
                    <SelectValue placeholder="Select your role" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="student">Student</SelectItem>
                    <SelectItem value="faculty">Faculty</SelectItem>
                    <SelectItem value="admin">Administrator</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {formData.role === "student" && (
                <div className="space-y-2">
                  <Label htmlFor="studentId" className="text-white">Student ID *</Label>
                  <div className="relative">
                    <GraduationCap className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                    <Input
                      id="studentId"
                      type="text"
                      value={formData.studentId}
                      onChange={(e) => handleInputChange("studentId", e.target.value)}
                      className="pl-10 bg-white/5 border-white/20 text-white placeholder-gray-400"
                      placeholder="Enter your student ID"
                      required
                    />
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="department" className="text-white">Department</Label>
                <div className="relative">
                  <Building className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <Input
                    id="department"
                    type="text"
                    value={formData.department}
                    onChange={(e) => handleInputChange("department", e.target.value)}
                    className="pl-10 bg-white/5 border-white/20 text-white placeholder-gray-400"
                    placeholder="Enter your department"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="password" className="text-white">Password *</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <Input
                    id="password"
                    type="password"
                    value={formData.password}
                    onChange={(e) => handleInputChange("password", e.target.value)}
                    className="pl-10 bg-white/5 border-white/20 text-white placeholder-gray-400"
                    placeholder="Create a password"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="confirmPassword" className="text-white">Confirm Password *</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <Input
                    id="confirmPassword"
                    type="password"
                    value={formData.confirmPassword}
                    onChange={(e) => handleInputChange("confirmPassword", e.target.value)}
                    className="pl-10 bg-white/5 border-white/20 text-white placeholder-gray-400"
                    placeholder="Confirm your password"
                    required
                  />
                </div>
              </div>

              <Button
                type="submit"
                disabled={isLoading}
                className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-semibold py-3 rounded-lg transition-all duration-200 transform hover:scale-105"
              >
                {isLoading ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <>
                    Create Account
                    <ArrowRight className="w-5 h-5 ml-2" />
                  </>
                )}
              </Button>
            </form>

            <div className="mt-6 text-center">
              <p className="text-gray-300">
                Already have an account?{" "}
                <Link href="/login" className="text-blue-400 hover:text-blue-300 font-semibold">
                  Sign in
                </Link>
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}