import { LoginCredentials, User } from '../types/auth';
import {
    hasRefreshToken as apiHasRefreshToken,
    isAuthenticated as apiIsAuthenticated,
    authApi,
    clearCsrfToken,
    getCsrfToken,
    refreshToken,
    setCsrfToken
} from './api';

// Check if user is authenticated
export const isAuthenticated = (): boolean => {
    return apiIsAuthenticated();
};

// Login function using API
export const login = async (credentials: LoginCredentials): Promise<{ success: boolean; user?: User; error?: string }> => {
    try {
        // Call the login API
        const response = await authApi.login(credentials.username, credentials.password);
        
        return {
            success: true,
            user: response.user,
        };
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Login failed',
        };
    }
};

// Get current user from API
export const getCurrentUser = async (): Promise<User | null> => {
    if (!isAuthenticated()) {
        return null;
    }
    
    try {
        // Call the API to get current user
        const user = await authApi.getCurrentUser();
        return user;
    } catch (error) {
        // If there's an error (like token expired), clear the CSRF token
        clearCsrfToken();
        return null;
    }
};

// Logout function
export const logout = async (): Promise<void> => {
    try {
        // Call the logout API
        await authApi.logout();
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        // Always clear the CSRF token, even if the API call fails
        clearCsrfToken();
    }
};

// Refresh token function
export const refreshAuthToken = async (): Promise<boolean> => {
    return refreshToken();
};

// Export CSRF token utility functions
export const getCsrfAuthToken = getCsrfToken;
export const setCsrfAuthToken = setCsrfToken;
export const clearCsrfAuthToken = clearCsrfToken;

// Export hasRefreshToken function
export const hasRefreshToken = apiHasRefreshToken;

// Keep these for backward compatibility
export const getAuthToken = getCsrfToken;
export const setAuthToken = setCsrfToken;
export const removeAuthToken = clearCsrfToken;
