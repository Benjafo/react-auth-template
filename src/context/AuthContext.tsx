import { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { AuthContextType, AuthState, LoginCredentials } from '../types/auth';
import {
    login as authLogin,
    logout as authLogout,
    getCurrentUser,
    isAuthenticated,
    refreshAuthToken
} from '../utils/auth';

// Default auth state
const defaultAuthState: AuthState = {
    user: null,
    isAuthenticated: false,
    isLoading: true,
    error: null,
};

// Token refresh interval (14 minutes = 840000ms)
// Slightly less than the token expiry time (15 minutes)
const TOKEN_REFRESH_INTERVAL = 840000;

// Create the auth context
export const AuthContext = createContext<AuthContextType>({
    ...defaultAuthState,
    login: async () => false,
    logout: async () => {},
    refreshToken: async () => false,
});

// Auth provider props
interface AuthProviderProps {
    children: ReactNode;
}

// Auth provider component
export const AuthProvider = ({ children }: AuthProviderProps) => {
    const [authState, setAuthState] = useState<AuthState>(defaultAuthState);
    const refreshTimerRef = useRef<number | null>(null);

    // Function to clear the refresh timer
    const clearRefreshTimer = useCallback(() => {
        if (refreshTimerRef.current) {
            window.clearTimeout(refreshTimerRef.current);
            refreshTimerRef.current = null;
        }
    }, []);

    // Function to set up the refresh timer
    const setupRefreshTimer = useCallback(() => {
        clearRefreshTimer();
        
        if (isAuthenticated()) {
            refreshTimerRef.current = window.setTimeout(async () => {
                await refreshToken();
                setupRefreshTimer(); // Set up the next refresh
            }, TOKEN_REFRESH_INTERVAL);
        }
    }, [clearRefreshTimer]);

    // Refresh token function
    const refreshToken = async (): Promise<boolean> => {
        try {
            const success = await refreshAuthToken();
            
            if (!success) {
                // If refresh failed, update auth state
                setAuthState({
                    user: null,
                    isAuthenticated: false,
                    isLoading: false,
                    error: 'Session expired. Please login again.',
                });
                clearRefreshTimer();
                return false;
            }
            
            // If refresh succeeded but we don't have user data, fetch it
            if (!authState.user && isAuthenticated()) {
                const user = await getCurrentUser();
                if (user) {
                    setAuthState(prev => ({
                        ...prev,
                        user,
                        isAuthenticated: true,
                    }));
                }
            }
            
            return true;
        } catch (error) {
            console.error('Token refresh error:', error);
            setAuthState({
                user: null,
                isAuthenticated: false,
                isLoading: false,
                error: 'Failed to refresh authentication',
            });
            clearRefreshTimer();
            return false;
        }
    };

    // Initialize auth state on mount
    useEffect(() => {
        const initializeAuth = async () => {
            try {
                if (isAuthenticated()) {
                    const user = await getCurrentUser();
                    setAuthState({
                        user,
                        isAuthenticated: !!user,
                        isLoading: false,
                        error: null,
                    });
                    
                    // Set up refresh timer if authenticated
                    if (user) {
                        setupRefreshTimer();
                    }
                } else {
                    setAuthState({
                        ...defaultAuthState,
                        isLoading: false,
                    });
                }
            } catch (error) {
                setAuthState({
                    ...defaultAuthState,
                    isLoading: false,
                    error: 'Failed to initialize authentication',
                });
            }
        };

        initializeAuth();
        
        // Clean up refresh timer on unmount
        return () => {
            clearRefreshTimer();
        };
    }, [clearRefreshTimer, setupRefreshTimer]);

    // Login function
    const login = async (credentials: LoginCredentials): Promise<boolean> => {
        setAuthState((prev) => ({
            ...prev,
            isLoading: true,
            error: null,
        }));

        try {
            const result = await authLogin(credentials);

            if (result.success && result.user) {
                setAuthState({
                    user: result.user,
                    isAuthenticated: true,
                    isLoading: false,
                    error: null,
                });
                
                // Set up refresh timer after successful login
                setupRefreshTimer();
                
                return true;
            } else {
                setAuthState((prev) => ({
                    ...prev,
                    isLoading: false,
                    error: result.error || 'Login failed',
                }));
                return false;
            }
        } catch (error) {
            setAuthState((prev) => ({
                ...prev,
                isLoading: false,
                error: 'An unexpected error occurred',
            }));
            return false;
        }
    };

    // Logout function
    const logout = async () => {
        try {
            await authLogout();
        } finally {
            // Clear refresh timer
            clearRefreshTimer();
            
            // Reset auth state
            setAuthState({
                user: null,
                isAuthenticated: false,
                isLoading: false,
                error: null,
            });
        }
    };

    // Auth context value
    const value: AuthContextType = {
        ...authState,
        login,
        logout,
        refreshToken,
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Custom hook to use auth context
export const useAuthContext = (): AuthContextType => {
    const context = useContext(AuthContext);
    
    if (!context) {
        throw new Error('useAuthContext must be used within an AuthProvider');
    }
    
    return context;
};
