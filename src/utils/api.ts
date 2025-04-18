// API constants
const API_URL = 'http://localhost:3001/api';

// CSRF token management
let csrfToken: string | null = null;

export const getCsrfToken = (): string | null => {
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

// Refresh token function
export const refreshToken = async (): Promise<boolean> => {
    try {
        const response = await fetch(`${API_URL}/refresh`, {
            method: 'POST',
            credentials: 'include', // Include cookies
            headers: {
                'Content-Type': 'application/json',
            },
        });

        if (!response.ok) {
            clearCsrfToken();
            return false;
        }

        const data = await response.json();
        setCsrfToken(data.csrfToken);
        return true;
    } catch (error) {
        console.error('Token refresh error:', error);
        clearCsrfToken();
        return false;
    }
};

// API request helper with token refresh
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
