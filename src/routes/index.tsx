import { Outlet, createRootRoute, createRoute, createRouter } from '@tanstack/react-router';
import AuthRequired from '../components/AuthRequired';
import { AuthProvider } from '../context/AuthContext';
import HomePage from '../pages/HomePage';
import LandingPage from '../pages/LandingPage';
import LoginPage from '../pages/LoginPage';

// Create the root route
const rootRoute = createRootRoute({
  component: () => (
    <AuthProvider>
      <div>
        <div id="content">
          <Outlet />
        </div>
      </div>
    </AuthProvider>
  ),
});

// Create the index route (home page)
const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: HomePage,
});

// Create the login route
const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: LoginPage,
});

// Create the landing route (protected)
const landingRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/landing',
  component: () => (
    <AuthRequired>
      <LandingPage />
    </AuthRequired>
  ),
});

// Create the route tree
const routeTree = rootRoute.addChildren([
  indexRoute,
  loginRoute,
  landingRoute,
]);

// Create the router
const router = createRouter({ routeTree });

// Export the router
export { router };
