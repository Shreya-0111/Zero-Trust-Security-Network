export type Role = "admin" | "faculty" | "user" | "student" | "visitor" | string

export function isRoleAllowed(userRole: Role | undefined, allowed: Role[]): boolean {
  if (!userRole) return false
  if (allowed.includes("admin")) {
    // still allow only listed roles; admin bypass handled below
  }
  if (userRole === "admin") return true
  return allowed.includes(userRole)
}
