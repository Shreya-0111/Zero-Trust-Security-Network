import { NextRequest, NextResponse } from "next/server"

const PUBLIC_FILE = /\.(.*)$/

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  if (
    pathname.startsWith("/login") ||
    pathname.startsWith("/signup") ||
    pathname.startsWith("/debug") ||
    pathname.startsWith("/test") ||
    pathname.startsWith("/auth-test") ||
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon") ||
    pathname.startsWith("/icon") ||
    pathname.startsWith("/apple-icon") ||
    PUBLIC_FILE.test(pathname)
  ) {
    return NextResponse.next()
  }

  const token = request.cookies.get("session_token")?.value
  if (!token) {
    const url = request.nextUrl.clone()
    url.pathname = "/login"
    url.searchParams.set("next", pathname)
    return NextResponse.redirect(url)
  }

  return NextResponse.next()
}

export const config = {
  matcher: ["/((?!api).*)"],
}
