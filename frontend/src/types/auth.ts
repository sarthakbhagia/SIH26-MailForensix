export interface User {
  id: string;
  email: string;
  role: 'admin' | 'analyst' | 'investigator' | 'viewer';
  org_id?: string;
  created_at: string;
  is_active: boolean;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
}
