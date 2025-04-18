import { Navigate, useNavigate } from '@tanstack/react-router';
import { ReactNode } from 'react';
import useAuth from '../hooks/useAuth';

interface AuthRequiredProps {
  children: ReactNode;
}

// Component to protect routes that require authentication
const AuthRequired = ({ children }: AuthRequiredProps) => {
  const { isAuthenticated, isLoading } = useAuth();
  const navigate = useNavigate();

  // Show loading state
  if (isLoading) {
    return <div>Loading...</div>;
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" />;
  }

  // Render children if authenticated
  return <>{children}</>;
};

export default AuthRequired;
