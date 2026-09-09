import React, { useState } from 'react';
import {
  X, LogIn, UserPlus, ShieldAlert, CheckCircle2,
  Lock, Mail, User, AlertCircle, Sparkles, KeyRound, ArrowRight
} from 'lucide-react';
import {
  isFirebaseConfigured,
  loginWithEmail,
  registerWithEmail,
  loginWithGoogle,
  resetPassword
} from '../lib/firebase';
import { useNotifications } from '../lib/notifications';

export default function AuthModal({ isOpen, onClose, mode = 'login', onLoginSuccess }) {
  const { notify } = useNotifications();

  const [authMode, setAuthMode] = useState(mode || 'login'); // 'login' | 'signup' | 'forgot'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [selectedRole, setSelectedRole] = useState('SOC Tier-2 Analyst');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  if (!isOpen) return null;

  const formatFirebaseError = (error) => {
    const code = error?.code || '';
    switch (code) {
      case 'auth/user-not-found':
      case 'auth/wrong-password':
      case 'auth/invalid-credential':
        return 'Invalid email or password. Please verify your credentials.';
      case 'auth/email-already-in-use':
        return 'An account with this security email already exists.';
      case 'auth/weak-password':
        return 'Password is too weak. Please use at least 6 characters.';
      case 'auth/invalid-email':
        return 'Please enter a valid email address.';
      case 'auth/popup-closed-by-user':
        return 'Google authentication popup was closed before completing.';
      case 'auth/network-request-failed':
        return 'Network connection error. Check your internet connectivity.';
      default:
        return error?.message || 'Authentication failed. Please try again.';
    }
  };

  const handleEmailAuth = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');
    setIsLoading(true);

    try {
      if (authMode === 'login') {
        const user = await loginWithEmail(email, password);
        const userData = {
          uid: user.uid,
          name: user.displayName || name || email.split('@')[0],
          email: user.email,
          role: selectedRole,
          photoURL: user.photoURL || null,
        };
        notify({
          severity: 'success',
          title: 'Authenticated Successfully',
          message: `Welcome back, ${userData.name}! Accessing ${selectedRole} workspace.`
        });
        onLoginSuccess(userData);
        onClose();
      } else if (authMode === 'signup') {
        const user = await registerWithEmail(email, password, name);
        const userData = {
          uid: user.uid,
          name: name || user.displayName || email.split('@')[0],
          email: user.email,
          role: selectedRole,
          photoURL: user.photoURL || null,
        };
        notify({
          severity: 'success',
          title: 'Account Registered',
          message: `SOC Analyst account created for ${userData.email}.`
        });
        onLoginSuccess(userData);
        onClose();
      } else if (authMode === 'forgot') {
        await resetPassword(email);
        setSuccessMessage(`Password reset link sent to ${email}. Check your inbox.`);
        setIsLoading(false);
      }
    } catch (err) {
      console.error('[Firebase Auth Error]', err);
      setErrorMessage(formatFirebaseError(err));
      setIsLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setErrorMessage('');
    setSuccessMessage('');
    setIsLoading(true);

    try {
      const user = await loginWithGoogle();
      const userData = {
        uid: user.uid,
        name: user.displayName || user.email.split('@')[0],
        email: user.email,
        role: selectedRole,
        photoURL: user.photoURL || null,
      };
      notify({
        severity: 'success',
        title: 'Google Authentication Verified',
        message: `Signed in as ${userData.name} (${selectedRole}).`
      });
      onLoginSuccess(userData);
      onClose();
    } catch (err) {
      console.error('[Google Auth Error]', err);
      setErrorMessage(formatFirebaseError(err));
      setIsLoading(false);
    }
  };

  const handleDemoBypass = () => {
    onLoginSuccess({
      uid: 'demo-analyst-001',
      name: name || 'Alex Rivera',
      email: email || 'alex@sentinel.ai',
      role: selectedRole,
    });
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-md animate-fadeIn">
      <div className="bg-white rounded-2xl p-6 sm:p-8 border border-slate-200 shadow-2xl max-w-md w-full relative space-y-5">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 text-slate-400 hover:text-slate-700 p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 border border-slate-200 transition cursor-pointer"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-700 text-white shadow-md shadow-blue-500/20">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-extrabold text-slate-900 tracking-tight">
              {authMode === 'login'
                ? 'Sign In to Sentinel AI'
                : authMode === 'signup'
                ? 'Create SOC Analyst Account'
                : 'Reset Analyst Password'}
            </h2>
            <p className="text-xs text-slate-500 font-medium">
              Firebase authenticated security console workspace
            </p>
          </div>
        </div>

        {/* Firebase Configuration Status Banner */}
        {!isFirebaseConfigured && (
          <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-900 space-y-1">
            <div className="flex items-center gap-1.5 font-bold">
              <AlertCircle className="w-4 h-4 text-amber-600 shrink-0" />
              <span>Firebase Keys Not Yet Configured in .env</span>
            </div>
            <p className="text-[11px] text-amber-800 leading-tight">
              Add <code className="bg-amber-100 px-1 py-0.5 rounded font-mono">VITE_FIREBASE_API_KEY</code> and <code className="bg-amber-100 px-1 py-0.5 rounded font-mono">VITE_FIREBASE_PROJECT_ID</code> to your <code className="font-bold">.env</code>.
            </p>
          </div>
        )}

        {/* Error / Success Alerts */}
        {errorMessage && (
          <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-800 flex items-start gap-2 animate-fadeIn">
            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
            <span className="font-semibold">{errorMessage}</span>
          </div>
        )}

        {successMessage && (
          <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 flex items-start gap-2 animate-fadeIn">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
            <span className="font-semibold">{successMessage}</span>
          </div>
        )}

        {/* Auth Mode Toggle */}
        {authMode !== 'forgot' && (
          <div className="flex rounded-xl bg-slate-100 p-1 border border-slate-200 text-xs">
            <button
              type="button"
              onClick={() => { setAuthMode('login'); setErrorMessage(''); }}
              className={`flex-1 py-2 rounded-lg font-bold transition cursor-pointer ${
                authMode === 'login' ? 'bg-white text-blue-700 shadow-xs border border-slate-200' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => { setAuthMode('signup'); setErrorMessage(''); }}
              className={`flex-1 py-2 rounded-lg font-bold transition cursor-pointer ${
                authMode === 'signup' ? 'bg-white text-blue-700 shadow-xs border border-slate-200' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Register
            </button>
          </div>
        )}

        {/* Google One-Click Button */}
        {authMode !== 'forgot' && isFirebaseConfigured && (
          <button
            type="button"
            disabled={isLoading}
            onClick={handleGoogleSignIn}
            className="w-full flex items-center justify-center gap-2.5 py-2.5 px-4 rounded-xl bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 font-bold text-xs transition shadow-2xs cursor-pointer active:scale-98 disabled:opacity-60"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
              />
            </svg>
            <span>Continue with Google Workspace</span>
          </button>
        )}

        {authMode !== 'forgot' && isFirebaseConfigured && (
          <div className="flex items-center gap-3">
            <div className="flex-1 h-px bg-slate-200" />
            <span className="text-[10px] font-mono text-slate-400 uppercase font-bold">or with email</span>
            <div className="flex-1 h-px bg-slate-200" />
          </div>
        )}

        {/* Email & Password Form */}
        <form onSubmit={handleEmailAuth} className="space-y-3.5 text-xs font-medium">
          {authMode === 'signup' && (
            <div>
              <label className="block text-slate-700 mb-1 font-bold">Full Name</label>
              <div className="relative">
                <User className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Alex Rivera"
                  className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-50 border border-slate-300 text-slate-900 focus:bg-white focus:outline-none focus:border-blue-600 font-medium"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-slate-700 mb-1 font-bold">Security Email</label>
            <div className="relative">
              <Mail className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@sentinel.ai"
                className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-50 border border-slate-300 text-slate-900 focus:bg-white focus:outline-none focus:border-blue-600 font-medium"
              />
            </div>
          </div>

          {authMode !== 'forgot' && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-slate-700 font-bold">Password</label>
                {authMode === 'login' && (
                  <button
                    type="button"
                    onClick={() => { setAuthMode('forgot'); setErrorMessage(''); setSuccessMessage(''); }}
                    className="text-[11px] text-blue-600 hover:text-blue-800 font-semibold cursor-pointer"
                  >
                    Forgot password?
                  </button>
                )}
              </div>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
                <input
                  type="password"
                  required
                  minLength={6}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-50 border border-slate-300 text-slate-900 focus:bg-white focus:outline-none focus:border-blue-600 font-medium"
                />
              </div>
            </div>
          )}

          {authMode !== 'forgot' && (
            <div>
              <label className="block text-slate-700 mb-1 font-bold">Operational Workspace Role</label>
              <select
                value={selectedRole}
                onChange={(e) => setSelectedRole(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-50 border border-slate-300 text-slate-900 focus:outline-none focus:border-blue-600 font-mono font-bold cursor-pointer"
              >
                <option value="SOC Tier-2 Analyst">SOC Tier-2 Analyst (Correlation & Graphs)</option>
                <option value="Detection Engineer">Detection Engineer (ML Models & Baselines)</option>
                <option value="IR Commander">IR Commander (Containment & Action Playbooks)</option>
              </select>
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-extrabold text-xs shadow-md shadow-blue-500/20 transition active:scale-98 cursor-pointer disabled:opacity-60 flex items-center justify-center gap-2"
          >
            {isLoading ? (
              <span>Authenticating...</span>
            ) : authMode === 'login' ? (
              <>
                <LogIn className="w-4 h-4" />
                <span>Sign In & Access SOC Console</span>
              </>
            ) : authMode === 'signup' ? (
              <>
                <UserPlus className="w-4 h-4" />
                <span>Create & Launch Workspace</span>
              </>
            ) : (
              <>
                <KeyRound className="w-4 h-4" />
                <span>Send Reset Link</span>
              </>
            )}
          </button>

          {authMode === 'forgot' && (
            <button
              type="button"
              onClick={() => { setAuthMode('login'); setErrorMessage(''); }}
              className="w-full text-center text-xs text-slate-600 hover:text-slate-900 font-bold mt-2 cursor-pointer"
            >
              ← Back to Sign In
            </button>
          )}
        </form>

        {/* Fallback Demo Mode Trigger if testing locally */}
        {!isFirebaseConfigured && (
          <div className="pt-2 border-t border-slate-200">
            <button
              type="button"
              onClick={handleDemoBypass}
              className="w-full py-2 px-3 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold text-xs transition cursor-pointer flex items-center justify-center gap-1.5"
            >
              <span>Continue with Local Demo Session</span>
              <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
