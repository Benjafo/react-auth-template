import { useNavigate } from '@tanstack/react-router';
import { FormEvent, useState } from 'react';
import NavBar from '../components/NavBar';
import useAuth from '../hooks/useAuth';
import { LoginCredentials } from '../types/auth';

// Login page component
const LoginPage = () => {
  const navigate = useNavigate();
  const { login, error, isLoading } = useAuth();
  const [credentials, setCredentials] = useState<LoginCredentials>({
    username: '',
    password: '',
  });

  // Handle input change
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setCredentials((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  // Handle form submission
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    
    const success = await login(credentials);
    
    if (success) {
      navigate({ to: '/landing' });
    }
  };

  return (
    <div>
      <NavBar />
      <div style={{ padding: '20px', maxWidth: '400px', margin: '0 auto' }}>
        <h1>Login</h1>
        
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '15px' }}>
            <label htmlFor="username" style={{ display: 'block', marginBottom: '5px' }}>
              Username
            </label>
            <input
              type="text"
              id="username"
              name="username"
              value={credentials.username}
              onChange={handleChange}
              required
              style={{ width: '100%', padding: '8px' }}
            />
          </div>
          
          <div style={{ marginBottom: '15px' }}>
            <label htmlFor="password" style={{ display: 'block', marginBottom: '5px' }}>
              Password
            </label>
            <input
              type="password"
              id="password"
              name="password"
              value={credentials.password}
              onChange={handleChange}
              required
              style={{ width: '100%', padding: '8px' }}
            />
          </div>
          
          {error && (
            <div style={{ color: 'red', marginBottom: '15px' }}>
              {error}
            </div>
          )}
          
          <button
            type="submit"
            disabled={isLoading}
            style={{ padding: '10px 15px', cursor: isLoading ? 'not-allowed' : 'pointer' }}
          >
            {isLoading ? 'Logging in...' : 'Login'}
          </button>
        </form>
        
        <div style={{ marginTop: '20px' }}>
          <p>Use the following credentials:</p>
          <ul>
            <li>Username: user</li>
            <li>Password: password</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
