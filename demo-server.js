import cookieParser from 'cookie-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

// Load environment variables
dotenv.config();

// Create Express app
const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'your-refresh-secret-key';
const ACCESS_TOKEN_EXPIRY = '15m'; // Short-lived access token
const REFRESH_TOKEN_EXPIRY = '7d'; // Longer-lived refresh token

// Store for refresh tokens and CSRF tokens (in a real app, use a database)
const refreshTokens = new Map();
const csrfTokens = new Map();

// Middleware
app.use(cors({
    origin: process.env.ORIGIN_URL | 'http://localhost:5173', // Your frontend URL
    credentials: true // Allow cookies to be sent
}));
app.use(express.json());
app.use(cookieParser());

// Rate limiting middleware
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 requests per windowMs per IP
    message: { message: 'Too many login attempts, please try again later' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Mock user database
const USERS = [
    {
        id: '1',
        username: 'user',
        email: 'user@example.com',
        password: 'password',
    },
];

// Generate tokens
const generateTokens = (user) => {
    // Generate access token
    const accessToken = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRY }
    );
    
    // Generate refresh token
    const refreshToken = jwt.sign(
        { id: user.id },
        REFRESH_TOKEN_SECRET,
        { expiresIn: REFRESH_TOKEN_EXPIRY }
    );
    
    // Store refresh token
    refreshTokens.set(user.id, refreshToken);
    
    return { accessToken, refreshToken };
};

// Set secure cookies
const setTokenCookies = (res, accessToken, refreshToken) => {
    // Set access token in HTTP-only cookie
    res.cookie('access_token', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Secure in production
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000, // 15 minutes in milliseconds
    });
    
    // Set refresh token in HTTP-only cookie
    res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Secure in production
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
    });
};

// Clear auth cookies
const clearTokenCookies = (res) => {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    res.clearCookie('csrf_token');
};

// Generate CSRF token
const generateCsrfToken = (userId) => {
    const csrfToken = uuidv4();
    csrfTokens.set(userId, csrfToken);
    return csrfToken;
};

// Middleware to verify CSRF token
const verifyCsrfToken = (req, res, next) => {
    const csrfToken = req.headers['x-csrf-token'];
    const userId = req.user?.id;
    
    if (!userId || !csrfToken || csrfTokens.get(userId) !== csrfToken) {
        return res.status(403).json({ message: 'Invalid CSRF token' });
    }
    
    next();
};

// Middleware to verify JWT token from cookies
const authenticateToken = (req, res, next) => {
    const accessToken = req.cookies.access_token;
    
    if (!accessToken) {
        return res.status(401).json({ message: 'Authentication required' });
    }
    
    jwt.verify(accessToken, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        
        req.user = user;
        next();
    });
};

// Login route with rate limiting
app.post('/api/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    
    // Find user
    const user = USERS.find(u => u.username === username && u.password === password);
    
    if (!user) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }
    
    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);
    
    // Set tokens in HTTP-only cookies
    setTokenCookies(res, accessToken, refreshToken);
    
    // Generate CSRF token
    const csrfToken = generateCsrfToken(user.id);
    
    // Set CSRF token in a regular cookie (accessible to JavaScript)
    res.cookie('csrf_token', csrfToken, {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000, // 15 minutes
    });
    
    // Return user info and CSRF token
    res.json({
        user: {
            id: user.id,
            username: user.username,
            email: user.email,
        },
        csrfToken,
    });
});

// Refresh token route
app.post('/api/refresh', (req, res) => {
    const refreshToken = req.cookies.refresh_token;
    
    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token required' });
    }
    
    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired refresh token' });
        }
        
        // Check if refresh token is in our store
        const storedToken = refreshTokens.get(user.id);
        if (!storedToken || storedToken !== refreshToken) {
            return res.status(403).json({ message: 'Refresh token revoked' });
        }
        
        // Find the user
        const userData = USERS.find(u => u.id === user.id);
        if (!userData) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Generate new tokens
        const { accessToken, refreshToken: newRefreshToken } = generateTokens(userData);
        
        // Set new tokens in HTTP-only cookies
        setTokenCookies(res, accessToken, newRefreshToken);
        
        // Generate new CSRF token
        const csrfToken = generateCsrfToken(userData.id);
        
        // Set CSRF token in a regular cookie
        res.cookie('csrf_token', csrfToken, {
            httpOnly: false,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15 * 60 * 1000, // 15 minutes
        });
        
        // Return success and CSRF token
        res.json({
            message: 'Token refreshed successfully',
            csrfToken,
        });
    });
});

// Get current user route (protected)
app.get('/api/user', authenticateToken, (req, res) => {
    const user = USERS.find(u => u.id === req.user.id);
    
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({
        id: user.id,
        username: user.username,
        email: user.email,
    });
});

// Logout route
app.post('/api/logout', authenticateToken, verifyCsrfToken, (req, res) => {
    // Remove refresh token from store
    refreshTokens.delete(req.user.id);
    
    // Remove CSRF token
    csrfTokens.delete(req.user.id);
    
    // Clear cookies
    clearTokenCookies(res);
    
    res.json({ message: 'Logout successful' });
});

// CSRF token endpoint (to get a new CSRF token if needed)
app.get('/api/csrf-token', authenticateToken, (req, res) => {
    const csrfToken = generateCsrfToken(req.user.id);
    
    // Set CSRF token in a regular cookie
    res.cookie('csrf_token', csrfToken, {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000, // 15 minutes
    });
    
    res.json({ csrfToken });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
