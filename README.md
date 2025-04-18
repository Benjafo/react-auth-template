# React Authentication Template

A secure React authentication template with TypeScript, featuring token refresh mechanism and enhanced security.

## Features

### Authentication System
- Complete authentication flow with login, logout, and protected routes
- Context API for global authentication state management
- TypeScript for type safety

### Enhanced Security
- **Token Refresh Mechanism**: Automatically refreshes access tokens before expiration
- **HTTP-only Cookies**: Securely stores tokens in HTTP-only cookies to prevent XSS attacks
- **CSRF Protection**: Implements Cross-Site Request Forgery protection
- **Rate Limiting**: Prevents brute force attacks on login endpoints

## Project Structure

```
src/
├── components/
│   ├── AuthRequired.tsx    # Protected route component
│   └── NavBar.tsx          # Navigation bar with auth-aware links
├── context/
│   └── AuthContext.tsx     # Authentication context provider
├── hooks/
│   └── useAuth.tsx         # Custom hook for using auth context
├── pages/
│   ├── HomePage.tsx        # Public home page
│   ├── LandingPage.tsx     # Protected landing page
│   └── LoginPage.tsx       # Login page
├── routes/
│   └── index.tsx           # Application routes
├── types/
│   └── auth.ts             # TypeScript interfaces for auth
└── utils/
    ├── api.ts              # API utilities with token refresh
    └── auth.ts             # Authentication utilities
```

## Backend Server

The project includes a demo Express server (`demo-server.js`) that implements:

- JWT-based authentication with access and refresh tokens
- HTTP-only cookies for secure token storage
- CSRF token generation and validation
- Rate limiting for login attempts

## Getting Started

1. Install dependencies:
   ```
   npm install
   ```

2. Start the development server and backend:
   ```
   npm run demo
   ```

3. Open [http://localhost:5173](http://localhost:5173) in your browser.

## Authentication Flow

1. **Login**: User submits credentials, server validates and returns:
   - Access token (short-lived, 15 minutes) in HTTP-only cookie
   - Refresh token (longer-lived, 7 days) in HTTP-only cookie
   - CSRF token for protection against CSRF attacks

2. **Token Refresh**: The system automatically refreshes tokens before expiration:
   - Refresh occurs 1 minute before access token expires
   - New tokens are issued and stored in HTTP-only cookies
   - New CSRF token is generated

3. **API Requests**:
   - Include credentials to send cookies
   - Include CSRF token in headers for state-changing requests
   - Automatically retry with fresh tokens if a request fails due to token expiration

4. **Logout**:
   - Clears tokens from cookies
   - Invalidates refresh token on the server
   - Resets authentication state

## Security Considerations

- **Access Tokens**: Short-lived (15 minutes) to minimize risk if compromised
- **Refresh Tokens**: Stored securely and rotated on use
- **CSRF Protection**: Required for all state-changing operations
- **HTTP-only Cookies**: Prevents JavaScript access to tokens
- **Rate Limiting**: Prevents brute force attacks

## Demo Credentials

- Username: `user`
- Password: `password`
