import { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { api, setAuthToken } from '@/lib/api';
import { User, AuthState, LoginCredentials, LoginResponse } from '@/types/auth';

interface AuthContextType extends AuthState {
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => void;
  refreshUser: () => Promise<void>;
  role: User['role'] | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const STORAGE_KEY = 'mailforensix_auth';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(() => {
    // Synchronous initial hydration from localStorage to prevent auth flicker
    try {
      if (typeof window !== 'undefined') {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
          const { token, user } = JSON.parse(stored);
          if (token && user) {
            const normalizedToken = token.startsWith('Bearer ')
              ? token
              : `Bearer ${token.replace(/^bearer\s+/i, '')}`;
            setAuthToken(normalizedToken);
            return {
              user,
              token: normalizedToken,
              isAuthenticated: true,
              isLoading: false,
            };
          }
        }
      }
    } catch (e) {
      console.warn('Failed to parse initial stored auth:', e);
    }
    return {
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: true,
    };
  });

  const loadStoredAuth = useCallback(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const { token, user } = JSON.parse(stored);
        if (token && user) {
          const normalizedToken = token.startsWith('Bearer ')
            ? token
            : `Bearer ${token.replace(/^bearer\s+/i, '')}`;
          setAuthToken(normalizedToken);
          setState({
            user,
            token: normalizedToken,
            isAuthenticated: true,
            isLoading: false,
          });
          return normalizedToken;
        }
      }
    } catch (e) {
      console.warn('Failed to parse stored auth:', e);
      localStorage.removeItem(STORAGE_KEY);
    }
    setAuthToken(null);
    setState(prev => ({ ...prev, isLoading: false }));
    return null;
  }, []);

  const saveAuth = useCallback((token: string, user: User) => {
    const normalizedToken = token.startsWith('Bearer ')
      ? token
      : `Bearer ${token.replace(/^bearer\s+/i, '')}`;
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ token: normalizedToken, user }));
    setAuthToken(normalizedToken);
    setState({ user, token: normalizedToken, isAuthenticated: true, isLoading: false });
  }, []);

  const clearAuth = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    setAuthToken(null);
    setState({ user: null, token: null, isAuthenticated: false, isLoading: false });
  }, []);

  const refreshUser = useCallback(async () => {
    const token = loadStoredAuth();
    if (!token) return;

    try {
      const response = await api.getCurrentUser();
      saveAuth(token, response.data);
    } catch (e) {
      console.warn('Token validation failed:', e);
      clearAuth();
    }
  }, [loadStoredAuth, saveAuth, clearAuth]);

  useEffect(() => {
    const token = loadStoredAuth();
    if (token) {
      refreshUser();
    }
  }, [loadStoredAuth, refreshUser]);

  const login = async (credentials: LoginCredentials) => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      const response = await api.login(credentials);
      const { access_token } = response.data as LoginResponse;
      const token = `Bearer ${access_token}`;
      setAuthToken(token);
      const userResponse = await api.getCurrentUser();
      saveAuth(token, userResponse.data);
    } catch (error: any) {
      clearAuth();
      const message =
        error.response?.data?.detail || error.message || 'Login failed. Please check your credentials.';
      throw new Error(message);
    }
  };

  const logout = () => {
    clearAuth();
  };

  return (
    <AuthContext.Provider
      value={{
        ...state,
        login,
        logout,
        refreshUser,
        role: state.user?.role ?? null,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
