import { LoginCredentials, User } from '../types/auth';
import { authApi, getToken, removeToken, setToken } from './api';

// Check if user is authenticated
export const isAuthenticated = (): boolean => {
  return !!getToken();
};

// Login function using API
export const doLogin = async (credentials: LoginCredentials): Promise<{ success: boolean; user?: User; error?: string }> => {
  try {
    // Call the login API
    const response = await authApi.login(credentials.username, credentials.password);
    
    // Store the token
    setToken(response.token);
    
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
    // If there's an error (like token expired), remove the token
    removeToken();
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
    // Always remove the token, even if the API call fails
    removeToken();
  }
};

// For backward compatibility with existing code
export const login = doLogin;
export const getAuthToken = getToken;
export const setAuthToken = setToken;
export const removeAuthToken = removeToken;
