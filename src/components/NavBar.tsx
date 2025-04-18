import { Link } from '@tanstack/react-router';
import useAuth from '../hooks/useAuth';

// Navigation bar component
const NavBar = () => {
  const { isAuthenticated, logout, user } = useAuth();

  return (
    <nav>
      <ul style={{ display: 'flex', listStyle: 'none', gap: '20px' }}>
        <li>
          <Link to="/">Home</Link>
        </li>
        
        {isAuthenticated ? (
          <>
            <li>
              <Link to="/landing">Landing</Link>
            </li>
            <li>
              <button style={{ justifyContent: 'start' }} onClick={logout}>Logout ({user?.username})</button>
            </li>
          </>
        ) : (
          <li>
            <Link to="/login">Login</Link>
          </li>
        )}
      </ul>
    </nav>
  );
};

export default NavBar;
