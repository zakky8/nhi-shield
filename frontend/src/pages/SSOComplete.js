import React, { useEffect, useContext } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import AuthContext from '../contexts/AuthContext';

export default function SSOComplete() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { login } = useContext(AuthContext);

  useEffect(() => {
    const token = params.get('token');
    const error = params.get('sso_error');

    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        login(token, { id: payload.userId, email: payload.email, role: payload.role, orgId: payload.orgId });
        navigate('/dashboard');
      } catch {
        navigate('/login?error=sso_token_invalid');
      }
    } else if (error) {
      navigate(`/login?error=${encodeURIComponent(error)}`);
    } else {
      navigate('/login');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center text-white">
      <div className="text-center">
        <div className="text-5xl mb-4 animate-spin">⟳</div>
        <p className="text-gray-400">Completing sign-in...</p>
      </div>
    </div>
  );
}
