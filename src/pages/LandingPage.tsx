import NavBar from '../components/NavBar';
import useAuth from '../hooks/useAuth';

// Landing page component (protected route)
const LandingPage = () => {
  const { user } = useAuth();

  return (
    <div>
      <NavBar />
      <div style={{ padding: '20px' }}>
        <h1>Welcome to the Protected Landing Page</h1>
        <p>
          Hello, <strong>{user?.username}</strong>! You are now viewing a protected page.
        </p>
        <p>
          This page is only accessible to authenticated users. If you log out, you will be
          redirected to the login page if you try to access this page again.
        </p>
        <div style={{ marginTop: '20px' }}>
          <h2>Your Profile</h2>
          <p>User ID: {user?.id}</p>
          <p>Username: {user?.username}</p>
          <p>Email: {user?.email}</p>
        </div>
      </div>
    </div>
  );
};

export default LandingPage;
