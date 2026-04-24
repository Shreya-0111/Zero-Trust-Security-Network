# Zero Trust Security Framework

A comprehensive, production-ready security framework implementing Zero Trust principles with advanced access control, visitor management, and real-time monitoring for educational institutions.

**Project Status: ✅ Fully Functional | 🚀 Production Ready | � Secudre**

## 🌟 Overview

This Zero Trust Security Framework provides a complete solution for modern institutional security needs, featuring:

- **Just-in-Time (JIT) Access Control** - Temporary elevated access with approval workflows
- **Emergency Break-Glass Access** - Critical incident response capabilities  
- **Visitor Management System** - Complete visitor registration and tracking
- **Device Fingerprinting** - Advanced device authentication and monitoring
- **Real-time Security Monitoring** - Live threat detection and response
- **Role-based Access Control** - Granular permission management
- **Firebase Integration** - Scalable authentication and data storage

---

## 🚀 Quick Start

### Break-Glass only (local)

If you only want the Emergency Break-Glass feature running locally (dev-login supported), follow: [BREAK_GLASS_LOCAL_GUIDE.md](BREAK_GLASS_LOCAL_GUIDE.md)

### Prerequisites

- **Node.js** 18+ and npm/pnpm
- **Python** 3.11+ 
- **Firebase** project with Authentication and Firestore enabled

### 🎯 Installation & Setup

**1. Clone and Setup Backend**
```bash
git clone https://github.com/AdityaC-0605/Zero-Trust-Security-Framework.git
cd Zero-Trust-Security-Framework/backend

# Create virtual environment and install dependencies
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Configure Firebase credentials
cp firebase-credentials.json.example firebase-credentials.json
# Add your Firebase service account key to firebase-credentials.json

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration
```

**2. Setup Frontend**
```bash
cd ../apps/security-ui

# Install dependencies
npm install

# Configure environment
cp .env.example .env.local
# Add your Firebase web app configuration to .env.local
```

**3. Initialize Database**
```bash
cd ../../backend
source venv/bin/activate

# Create default resource segments
python create_default_resources.py

# Create test users (optional)
python create_test_user.py
```

**4. Start the Application**

**Option A: Start Both Services**
```bash
# From project root
./start_all.sh
```

**Option B: Start Individually**
```bash
# Terminal 1: Backend
./start_backend.sh

# Terminal 2: Frontend  
./start_frontend.sh
```

**5. Access the Application**
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5001
- **Health Check**: http://localhost:5001/health

---

## 🏗️ Architecture

### System Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   Firebase      │
│   (Next.js)     │◄──►│   (Flask)       │◄──►│   (Auth/DB)     │
│   Port: 3000    │    │   Port: 5001    │    │   Cloud         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Key Features

#### 🔐 **Authentication & Authorization**
- Firebase Authentication integration
- JWT-based session management
- Role-based access control (Student, Faculty, Admin, User)
- Multi-factor authentication support
- Session timeout and refresh

#### 🎯 **Just-in-Time Access**
- Temporary elevated permissions
- Approval workflow system
- Time-limited access grants
- Audit trail for all access requests
- Risk-based access decisions

#### 🚨 **Emergency Access (Break Glass)**
- Critical incident response
- Emergency resource access
- Automatic audit logging
- Post-incident analysis
- Compliance reporting

#### 👥 **Visitor Management**
- Digital visitor registration
- Photo capture and verification
- QR code generation
- Real-time visitor tracking
- Host notification system
- Compliance monitoring

#### 🖥️ **Device Management**
- Device fingerprinting
- Trusted device registration
- Anomaly detection
- Device-based access control
- Security posture assessment

#### 📊 **Monitoring & Analytics**
- Real-time security dashboard
- Threat detection and response
- Performance monitoring
- Audit log management
- Compliance reporting

---

## 📁 Project Structure

```
Zero-Trust-Security-Framework/
├── apps/
│   └── security-ui/              # Next.js Frontend Application
│       ├── app/                  # App Router pages
│       │   ├── login/           # Authentication pages
│       │   ├── jit-access/      # JIT access requests
│       │   ├── emergency-access/ # Break glass access
│       │   ├── visitor-registration/ # Visitor management
│       │   ├── device-management/ # Device control
│       │   └── admin-dashboard/  # Administrative interface
│       ├── components/           # Reusable UI components
│       ├── hooks/               # Custom React hooks
│       ├── lib/                 # Utilities and API client
│       └── middleware.ts        # Authentication middleware
│
├── backend/                      # Flask Backend Application
│   ├── app/
│   │   ├── routes/              # API endpoints
│   │   │   ├── auth_routes.py   # Authentication
│   │   │   ├── jit_access_routes.py # JIT access
│   │   │   ├── break_glass_routes.py # Emergency access
│   │   │   ├── visitor_routes.py # Visitor management
│   │   │   ├── device_routes.py  # Device management
│   │   │   └── monitoring_routes.py # System monitoring
│   │   ├── services/            # Business logic
│   │   │   ├── auth_service_simple.py
│   │   │   ├── jit_access_service.py
│   │   │   ├── visitor_service.py
│   │   │   ├── device_fingerprint_service.py
│   │   │   └── enhanced_firebase_service.py
│   │   ├── models/              # Data models
│   │   │   ├── user.py
│   │   │   ├── resource_segment.py
│   │   │   ├── visitor.py
│   │   │   └── device_fingerprint.py
│   │   └── middleware/          # Request middleware
│   ├── tests/                   # Comprehensive test suite
│   └── requirements.txt         # Python dependencies
│
├── start_all.sh                 # Start both services
├── start_backend.sh             # Start backend only
├── start_frontend.sh            # Start frontend only
└── README.md                    # This file
```

---

## 🔧 Configuration

### Backend Environment Variables (.env)

```bash
# Flask Configuration
FLASK_ENV=development
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret

# Firebase Configuration
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_PRIVATE_KEY_ID=your-private-key-id
FIREBASE_PRIVATE_KEY=your-private-key
FIREBASE_CLIENT_EMAIL=your-client-email
FIREBASE_CLIENT_ID=your-client-id

# Security Configuration
ENCRYPTION_KEY=your-encryption-key
AUDIT_ENCRYPTION_KEY=your-audit-key

# CORS Configuration
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Test User Configuration (Optional)
TEST_USER_EMAIL=test@example.com
TEST_USER_PASSWORD=your-secure-password
TEST_USER_NAME=Test User
```

**⚠️ Security Note**: Never commit `.env` files or hardcode credentials in your code. Use the provided `.env.example` as a template.

### Frontend Environment Variables (.env.local)

```bash
# Backend API
NEXT_PUBLIC_API_URL=http://localhost:5001
NEXT_PUBLIC_BACKEND_URL=http://localhost:5001

# Firebase Web Configuration
NEXT_PUBLIC_FIREBASE_API_KEY=your-api-key
NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
NEXT_PUBLIC_FIREBASE_PROJECT_ID=your-project-id
NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=your-project.appspot.com
NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=your-sender-id
NEXT_PUBLIC_FIREBASE_APP_ID=your-app-id
```

---

## 🎯 User Roles & Permissions

### Role Hierarchy

| Role | Security Clearance | Access Level | Capabilities |
|------|-------------------|--------------|--------------|
| **Student** | Level 1 | Basic | Library access, basic resources |
| **User** | Level 3 | Standard | Email systems, student records (JIT), research data (JIT) |
| **Faculty** | Level 3 | Standard | Same as User + teaching resources |
| **Admin** | Level 5 | Full | All systems, emergency access, user management |

### Resource Access Matrix

| Resource | Student | User | Faculty | Admin | JIT Required |
|----------|---------|------|---------|-------|--------------|
| Library Management | ✅ | ✅ | ✅ | ✅ | No |
| Email Administration | ❌ | ✅ | ✅ | ✅ | No |
| Student Records | ❌ | 🔑 | 🔑 | ✅ | Yes |
| Research Data | ❌ | 🔑 | 🔑 | ✅ | Yes |
| Financial Systems | ❌ | ❌ | ❌ | 🔑 | Yes |
| Security Cameras | ❌ | ❌ | ❌ | 🔑 | Yes |
| Network Infrastructure | ❌ | ❌ | ❌ | 🔑 | Yes |
| Emergency Communications | ❌ | ❌ | ❌ | 🔑 | Yes |

*Legend: ✅ Direct Access | 🔑 JIT Access Required | ❌ No Access*

---

## 🧪 Testing

### Run Test Suite

```bash
cd backend
source venv/bin/activate

# Run all tests
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/test_*_unit.py -v          # Unit tests
python -m pytest tests/test_*_integration.py -v   # Integration tests
python -m pytest tests/test_performance_*.py -v   # Performance tests
```

### Manual Testing

```bash
# Test backend health
curl http://localhost:5001/health

# Test authentication
curl -X POST http://localhost:5001/api/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"idToken": "your-firebase-token"}'

# Test resource segments
curl http://localhost:5001/api/resource-segments/available \
  -H "Cookie: session_token=your-session-token"
```

---

## 🚀 Deployment

### Production Deployment

**1. Backend (Flask)**
```bash
# Use production WSGI server
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5001 run:app

# Or use Docker
docker build -f Dockerfile.prod -t zero-trust-backend .
docker run -p 5001:5001 zero-trust-backend
```

**2. Frontend (Next.js)**
```bash
# Build for production
npm run build
npm start

# Or use Docker
docker build -t zero-trust-frontend .
docker run -p 3000:3000 zero-trust-frontend
```

### Environment Setup

- Set `FLASK_ENV=production` in backend
- Configure proper Firebase credentials
- Set secure `SECRET_KEY` and `JWT_SECRET_KEY`
- Enable HTTPS in production
- Configure proper CORS origins

---

## 📊 Monitoring & Observability

### Health Checks

- **Backend Health**: `GET /health`
- **Auth Service**: `GET /api/auth/health`
- **Database**: `GET /api/system/health`

### Metrics & Logging

- Request/response metrics
- Authentication events
- Access control decisions
- Security incidents
- Performance monitoring

### Audit Trail

All security-relevant events are logged:
- Authentication attempts
- Access requests and approvals
- Emergency access usage
- Configuration changes
- Security incidents

---

## 🔒 Security Features

### Zero Trust Principles

1. **Never Trust, Always Verify** - Every request is authenticated and authorized
2. **Least Privilege Access** - Minimal permissions by default
3. **Assume Breach** - Continuous monitoring and verification
4. **Verify Explicitly** - Multi-factor authentication and device verification

### Security Controls

- **Encryption**: Data encrypted at rest and in transit
- **Authentication**: Multi-factor authentication support
- **Authorization**: Role-based and attribute-based access control
- **Audit Logging**: Comprehensive security event logging
- **Session Management**: Secure session handling with timeout
- **Input Validation**: All inputs validated and sanitized
- **CSRF Protection**: Cross-site request forgery protection
- **Rate Limiting**: API rate limiting and abuse prevention

---

## 🤝 Contributing

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Run the test suite: `pytest tests/`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

### Code Standards

- **Python**: Follow PEP 8, use type hints
- **TypeScript**: Use strict mode, proper typing
- **Testing**: Maintain >90% test coverage
- **Documentation**: Update README and inline docs
- **Security**: Follow OWASP guidelines

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📞 Support

### Documentation

- **Quick Start**: See [QUICK_START.md](QUICK_START.md)
- **API Documentation**: Available at `/api/docs` when running
- **Architecture Guide**: See `/docs/architecture.md`

### Getting Help

1. Check the [Issues](https://github.com/AdityaC-0605/Zero-Trust-Security-Framework/issues) page
2. Review the troubleshooting section above
3. Create a new issue with detailed information

### Troubleshooting

**Common Issues:**

1. **Port conflicts**: Kill existing processes on ports 3000/5001
2. **Firebase errors**: Verify credentials and project configuration
3. **Permission errors**: Check user roles and resource access matrix
4. **Session issues**: Clear browser cookies and restart services

---

**Project Status**: ✅ Production Ready | 🔒 Secure | 🚀 Scalable  
**Last Updated**: December 28, 2024  
**Version**: 2.0.0  
**Maintainer**: [AdityaC-0605](https://github.com/AdityaC-0605)