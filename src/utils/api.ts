// API constants
const API_URL = 'http://localhost:3001/api';

// Local storage keys
const ACCESS_TOKEN_STORAGE_KEY = 'access_token';

// Token management
let accessToken: string | null = null;
let csrfToken: string | null = null;

// Initialize access token from localStorage if available
const initAccessTokenFromStorage = (): void => {
    try {
        const storedToken = localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY);
        if (storedToken) {
            accessToken = storedToken;
        }
    } catch (error) {
        console.error('Error initializing access token from storage:', error);
    }
};

// Initialize tokens on module load
initAccessTokenFromStorage();

// Initialize CSRF token from cookie if available
const initCsrfTokenFromCookie = (): void => {
    try {
        // Try to get the CSRF token from the cookie
        const cookies = document.cookie.split(';');
        const csrfCookie = cookies.find(cookie => cookie.trim().startsWith('csrf_token='));
        
        if (csrfCookie) {
            const cookieValue = csrfCookie.split('=')[1];
            if (cookieValue) {
                csrfToken = cookieValue;
            }
        }
    } catch (error) {
        console.error('Error initializing CSRF token from cookie:', error);
    }
};

// Initialize the CSRF token from cookie on module load
initCsrfTokenFromCookie();

// Access token management
export const getAccessToken = (): string | null => {
    // If token is not in memory, try to get it from localStorage
    if (!accessToken) {
        initAccessTokenFromStorage();
    }
    return accessToken;
};

export const setAccessToken = (token: string): void => {
    accessToken = token;
    // Also store in localStorage for persistence across page refreshes
    try {
        localStorage.setItem(ACCESS_TOKEN_STORAGE_KEY, token);
    } catch (error) {
        console.error('Error storing access token in localStorage:', error);
    }
};

export const clearAccessToken = (): void => {
    accessToken = null;
    // Also remove from localStorage
    try {
        localStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY);
    } catch (error) {
        console.error('Error removing access token from localStorage:', error);
    }
};

// CSRF token management
export const getCsrfToken = (): string | null => {
    // If token is not in memory, try to get it from cookie
    if (!csrfToken) {
        initCsrfTokenFromCookie();
    }
    return csrfToken;
};

export const setCsrfToken = (token: string): void => {
    csrfToken = token;
};

export const clearCsrfToken = (): void => {
    csrfToken = null;
};

// Clear all tokens
export const clearAllTokens = (): void => {
    clearAccessToken();
    clearCsrfToken();
};

// For backward compatibility
export const getToken = (): string | null => getAccessToken();
export const setToken = (token: string): void => setAccessToken(token);
export const removeToken = (): void => clearAccessToken();

// Check if user is authenticated (based on access token presence)
export const isAuthenticated = (): boolean => {
    return !!accessToken;
};

// Create headers with Authorization and CSRF token
const createHeaders = (includeAuth: boolean = true): HeadersInit => {
    const headers: HeadersInit = {
        'Content-Type': 'application/json',
    };

    // Add Authorization header with Bearer token if we have an access token
    if (includeAuth && accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`;
    }

    // Add CSRF token for operations that require it (like using refresh token)
    if (includeAuth && csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
    }

    return headers;
};

// Check if HTTP-only cookies exist (specifically the refresh_token)
// This is a heuristic since JavaScript can't directly access HTTP-only cookies
export const hasRefreshToken = (): boolean => {
    // We can't directly check for HTTP-only cookies, but we can make an educated guess
    // If we've previously authenticated and the page was just refreshed,
    // the HTTP-only cookies should still be there even if the CSRF token in memory is gone
    
    // Try to get the CSRF token from the cookie first
    initCsrfTokenFromCookie();
    
    // If we have a CSRF token in the cookie, it's likely we also have HTTP-only cookies
    if (csrfToken) {
        return true;
    }
    
    // Otherwise, we'll have to try a refresh to see if we have valid HTTP-only cookies
    return false;
};

// Refresh token function
// This function attempts to refresh the access token using the existing refresh token
// If successful, it updates the access token and CSRF token and returns true
// If unsuccessful (refresh token expired or invalid), it clears all tokens and returns false,
// which will trigger a logout in the AuthContext
export const refreshToken = async (): Promise<boolean> => {
    try {
        console.log('Attempting to refresh token...');
        
        const response = await fetch(`${API_URL}/refresh`, {
            method: 'POST',
            credentials: 'include', // Include cookies for refresh token
            headers: {
                'Content-Type': 'application/json',
            },
        });

        if (!response.ok) {
            console.log('Token refresh failed with status:', response.status);
            // If refresh fails (e.g., refresh token expired), clear all tokens
            // This will be detected by AuthContext which will trigger a logout
            clearAllTokens();
            return false;
        }

        const data = await response.json();
        console.log('Token refresh succeeded, got new access token and CSRF token');
        setAccessToken(data.accessToken);
        setCsrfToken(data.csrfToken);
        return true;
    } catch (error) {
        console.error('Token refresh error:', error);
        clearAllTokens();
        return false;
    }
};

// API request helper with token refresh
// This function handles API requests and automatically attempts to refresh the token
// if a request fails due to an expired access token
const apiRequest = async <T>(
    endpoint: string,
    method: string = 'GET',
    data?: any,
    includeAuth: boolean = true,
    retryOnUnauthorized: boolean = true
): Promise<T> => {
    const url = `${API_URL}${endpoint}`;
    const headers = createHeaders(includeAuth);

    const config: RequestInit = {
        method,
        headers,
        // credentials: endpoint === '/refresh' ? 'include' : 'same-origin', // Only include cookies for refresh
        credentials: 'include',
        body: data ? JSON.stringify(data) : undefined,
    };

    try {
        const response = await fetch(url, config);

        // Handle unauthorized error (expired token)
        if ((response.status === 401 || response.status === 403) && retryOnUnauthorized) {
            // Try to refresh the token
            const refreshed = await refreshToken();
            if (refreshed) {
                // Retry the request with the new token
                return apiRequest<T>(endpoint, method, data, includeAuth, false);
            } else {
                // If refresh fails (e.g., refresh token expired), clear all tokens
                // This will be detected by AuthContext which will trigger a logout
                clearAllTokens();
                throw new Error('Session expired. Please login again.');
            }
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'API request failed');
        }

        return await response.json();
    } catch (error) {
        console.error('API request error:', error);
        throw error;
    }
};

// Auth API endpoints
export const authApi = {
    login: async (username: string, password: string) => {
        const response = await apiRequest<{ user: any; accessToken: string; csrfToken: string }>(
            '/login',
            'POST',
            { username, password },
            false,
            false // Don't retry on unauthorized for login
        );
        
        // Store the tokens
        setAccessToken(response.accessToken);
        setCsrfToken(response.csrfToken);
        
        return {
            user: response.user,
            token: response.accessToken, // For backward compatibility
        };
    },

    getCurrentUser: async () => {
        return apiRequest<any>('/user');
    },

    logout: async () => {
        try {
            await apiRequest<{ message: string }>('/logout', 'POST');
        } finally {
            clearAllTokens();
        }
    },
    
    refreshCsrfToken: async () => {
        return apiRequest<{ csrfToken: string }>('/csrf-token', 'GET');
    },
};
