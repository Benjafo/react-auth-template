// API constants
const API_URL = 'http://localhost:3001/api';

// CSRF token management
let csrfToken: string | null = null;

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

// For backward compatibility - these functions don't do anything with HTTP-only cookies
// but are kept to maintain the same interface
export const getToken = (): string | undefined => undefined;
export const setToken = (_token: string): void => {};
export const removeToken = (): void => {};

// Check if user is authenticated (based on CSRF token presence)
export const isAuthenticated = (): boolean => {
    return !!csrfToken;
};

// Create headers with CSRF token
const createHeaders = (includeAuth: boolean = true): HeadersInit => {
    const headers: HeadersInit = {
        'Content-Type': 'application/json',
    };

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
// If successful, it updates the CSRF token and returns true
// If unsuccessful (refresh token expired or invalid), it clears the CSRF token and returns false,
// which will trigger a logout in the AuthContext
export const refreshToken = async (): Promise<boolean> => {
    try {
        console.log('Attempting to refresh token...');
        
        const response = await fetch(`${API_URL}/refresh`, {
            method: 'POST',
            credentials: 'include', // Include cookies
            headers: {
                'Content-Type': 'application/json',
            },
        });

        if (!response.ok) {
            console.log('Token refresh failed with status:', response.status);
            // If refresh fails (e.g., refresh token expired), clear CSRF token
            // This will be detected by AuthContext which will trigger a logout
            clearCsrfToken();
            return false;
        }

        const data = await response.json();
        console.log('Token refresh succeeded, got new CSRF token');
        setCsrfToken(data.csrfToken);
        return true;
    } catch (error) {
        console.error('Token refresh error:', error);
        clearCsrfToken();
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
        credentials: 'include', // Include cookies in request
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
                // If refresh fails (e.g., refresh token expired), clear CSRF token
                // This will be detected by AuthContext which will trigger a logout
                clearCsrfToken();
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
        const response = await apiRequest<{ user: any; csrfToken: string }>(
            '/login',
            'POST',
            { username, password },
            false,
            false // Don't retry on unauthorized for login
        );
        
        // Store the CSRF token
        setCsrfToken(response.csrfToken);
        
        return {
            user: response.user,
            token: response.csrfToken, // For backward compatibility
        };
    },

    getCurrentUser: async () => {
        return apiRequest<any>('/user');
    },

    logout: async () => {
        try {
            await apiRequest<{ message: string }>('/logout', 'POST');
        } finally {
            clearCsrfToken();
        }
    },
    
    refreshCsrfToken: async () => {
        return apiRequest<{ csrfToken: string }>('/csrf-token', 'GET');
    },
};
