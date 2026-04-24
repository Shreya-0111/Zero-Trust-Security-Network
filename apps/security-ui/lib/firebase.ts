import { initializeApp, getApps } from "firebase/app"
import { getAuth } from "firebase/auth"

const isBrowser = typeof window !== "undefined"

// Get Firebase configuration from environment variables
const getFirebaseConfig = () => {
  const config = {
    apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
    authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
    projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
    storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID
  }

  // Check if all required config values are present
  const requiredFields = ['apiKey', 'authDomain', 'projectId', 'storageBucket', 'messagingSenderId', 'appId']
  const missingFields = requiredFields.filter(field => !config[field as keyof typeof config])
  
  if (missingFields.length > 0) {
    console.error('❌ Missing Firebase environment variables:', missingFields)
    return null
  }

  return config
}

const firebaseConfig = getFirebaseConfig()

// Debug logging
if (isBrowser && firebaseConfig) {
  console.log('🔥 Firebase Config loaded from environment:', {
    apiKey: firebaseConfig.apiKey.substring(0, 10) + '...',
    authDomain: firebaseConfig.authDomain,
    projectId: firebaseConfig.projectId,
    messagingSenderId: firebaseConfig.messagingSenderId,
    appId: firebaseConfig.appId.substring(0, 20) + '...'
  })
} else if (isBrowser) {
  console.error('❌ Firebase configuration not available - check environment variables')
}

let app = null
let initError = null

try {
  if (firebaseConfig && isBrowser) {
    app = getApps().length ? getApps()[0]! : initializeApp(firebaseConfig)
    console.log('✅ Firebase initialized successfully')
  }
} catch (error) {
  initError = error
  if (isBrowser) {
    console.error('❌ Firebase initialization failed:', error)
  }
}

export const auth = app ? getAuth(app) : null

// Export config status for debugging
export const firebaseConfigStatus = {
  hasRealConfig: !!firebaseConfig,
  config: firebaseConfig,
  isConfigured: !!app,
  initError,
  envVarsLoaded: {
    apiKey: !!process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
    authDomain: !!process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
    projectId: !!process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
    storageBucket: !!process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
    messagingSenderId: !!process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
    appId: !!process.env.NEXT_PUBLIC_FIREBASE_APP_ID
  }
}
