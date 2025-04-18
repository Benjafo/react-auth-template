import Cookies from 'js-cookie';

// API constants
const API_URL = 'http://localhost:3001/api';
const AUTH_TOKEN_KEY = 'auth_token';

// Get stored token
export const getToken = (): string | undefined => {
  return Cookies.get(AUTH_TOKEN_KEY);
};

// Store token in cookies
export const setToken = (token: string): void => {
  Cookies.set(AUTH_TOKEN_KEY, token, { expires: 7 }); // 7 days
};

// Remove token from cookies
export const removeToken = (): void => {
  Cookies.remove(AUTH_TOKEN_KEY);
};

// Create headers with authorization token
const createHeaders = (includeAuth: boolean = true): HeadersInit => {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };

  if (includeAuth) {
    const token = getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
  }

  return headers;
};

// API request helper
const apiRequest = async <T>(
  endpoint: string,
  method: string = 'GET',
  data?: any,
  includeAuth: boolean = true
): Promise<T> => {
  const url = `${API_URL}${endpoint}`;
  const headers = createHeaders(includeAuth);

  const config: RequestInit = {
    method,
    headers,
    body: data ? JSON.stringify(data) : undefined,
  };

  try {
    const response = await fetch(url, config);
    
    if (!response.ok) {
      // Handle unauthorized error (expired token)
      if (response.status === 401 || response.status === 403) {
        removeToken();
      }
      
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
    return apiRequest<{ user: any; token: string }>(
      '/login',
      'POST',
      { username, password },
      false
    );
  },
  
  getCurrentUser: async () => {
    return apiRequest<any>('/user');
  },
  
  logout: async () => {
    return apiRequest<{ message: string }>('/logout', 'POST');
  },
};
