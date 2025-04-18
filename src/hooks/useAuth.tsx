import { useAuthContext } from '../context/AuthContext';
import { AuthContextType } from '../types/auth';

// Custom hook to use authentication
export const useAuth = (): AuthContextType => {
  return useAuthContext();
};

export default useAuth;
