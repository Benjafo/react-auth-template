import NavBar from '../components/NavBar';

// Home page component
const HomePage = () => {
  return (
    <div>
      <NavBar />
      <div style={{ padding: '20px' }}>
        <h1>Welcome to the Authentication Demo</h1>
        <p>This is a public page that anyone can access.</p>
        <p>
          To see protected content, please login using the following credentials:
        </p>
        <ul>
          <li>Username: user</li>
          <li>Password: password</li>
        </ul>
      </div>
    </div>
  );
};

export default HomePage;
