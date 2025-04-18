import Cookies from 'js-cookie';
import { LoginCredentials, User } from '../types/auth';

// Token constants
const AUTH_TOKEN_KEY = 'auth_token';
const TOKEN_EXPIRY_DAYS = 7;

// Mock user database for frontend-only authentication
const MOCK_USERS = [
  {
    id: '1',
    username: 'user',
    email: 'user@example.com',
    password: 'password',
  },
];

// Store authentication token in cookies
export const setAuthToken = (token: string): void => {
  Cookies.set(AUTH_TOKEN_KEY, token, { expires: TOKEN_EXPIRY_DAYS });
};

// Retrieve authentication token from cookies
export const getAuthToken = (): string | undefined => {
  return Cookies.get(AUTH_TOKEN_KEY);
};

// Remove authentication token from cookies
export const removeAuthToken = (): void => {
  Cookies.remove(AUTH_TOKEN_KEY);
};

// Check if user is authenticated
export const isAuthenticated = (): boolean => {
  return !!getAuthToken();
};

// Mock login function
export const mockLogin = async (credentials: LoginCredentials): Promise<{ success: boolean; user?: User; error?: string }> => {
  // Simulate API call delay
  await new Promise((resolve) => setTimeout(resolve, 500));

  const user = MOCK_USERS.find(
    (u) => u.username === credentials.username && u.password === credentials.password
  );

  if (user) {
    // Generate a mock token
    const token = btoa(JSON.stringify({ id: user.id, username: user.username }));
    setAuthToken(token);
    
    return {
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
    };
  }

  return {
    success: false,
    error: 'Invalid username or password',
  };
};

// Get current user from token
export const getCurrentUser = (): User | null => {
  const token = getAuthToken();
  
  if (!token) {
    return null;
  }
  
  try {
    // In a real app, you would validate and decode the JWT token
    // Here we're just parsing our mock token
    const userData = JSON.parse(atob(token));
    const user = MOCK_USERS.find((u) => u.id === userData.id);
    
    if (!user) {
      return null;
    }
    
    return {
      id: user.id,
      username: user.username,
      email: user.email,
    };
  } catch (error) {
    removeAuthToken();
    return null;
  }
};
