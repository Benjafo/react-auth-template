import { createContext, ReactNode, useContext, useEffect, useState } from 'react';
import { AuthContextType, AuthState, LoginCredentials } from '../types/auth';
import { getCurrentUser, isAuthenticated, mockLogin, removeAuthToken } from '../utils/auth';

// Default auth state
const defaultAuthState: AuthState = {
  user: null,
  isAuthenticated: false,
  isLoading: true,
  error: null,
};

// Create the auth context
export const AuthContext = createContext<AuthContextType>({
  ...defaultAuthState,
  login: async () => false,
  logout: () => {},
});

// Auth provider props
interface AuthProviderProps {
  children: ReactNode;
}

// Auth provider component
export const AuthProvider = ({ children }: AuthProviderProps) => {
  const [authState, setAuthState] = useState<AuthState>(defaultAuthState);

  // Initialize auth state on mount
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        if (isAuthenticated()) {
          const user = getCurrentUser();
          setAuthState({
            user,
            isAuthenticated: !!user,
            isLoading: false,
            error: null,
          });
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
  }, []);

  // Login function
  const login = async (credentials: LoginCredentials): Promise<boolean> => {
    setAuthState((prev) => ({
      ...prev,
      isLoading: true,
      error: null,
    }));

    try {
      const result = await mockLogin(credentials);

      if (result.success && result.user) {
        setAuthState({
          user: result.user,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });
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
  const logout = () => {
    removeAuthToken();
    setAuthState({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
    });
  };

  // Auth context value
  const value: AuthContextType = {
    ...authState,
    login,
    logout,
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
