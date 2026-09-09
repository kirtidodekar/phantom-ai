import { initializeApp, getApps, getApp } from 'firebase/app';
import {
  getAuth,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signInWithPopup,
  GoogleAuthProvider,
  signOut,
  onAuthStateChanged,
  updateProfile,
  sendPasswordResetEmail
} from 'firebase/auth';

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || import.meta.env.FIREBASE_API_KEY || '',
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || import.meta.env.FIREBASE_AUTH_DOMAIN || '',
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || import.meta.env.FIREBASE_PROJECT_ID || '',
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || import.meta.env.FIREBASE_STORAGE_BUCKET || '',
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || import.meta.env.FIREBASE_MESSAGING_SENDER_ID || '',
  appId: import.meta.env.VITE_FIREBASE_APP_ID || import.meta.env.FIREBASE_APP_ID || '',
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID || import.meta.env.FIREBASE_MEASUREMENT_ID || '',
};

export const isFirebaseConfigured = Boolean(
  firebaseConfig.apiKey &&
  firebaseConfig.apiKey !== 'YOUR_FIREBASE_API_KEY' &&
  firebaseConfig.projectId
);

// Initialize Firebase safely
const app = isFirebaseConfigured
  ? (getApps().length === 0 ? initializeApp(firebaseConfig) : getApp())
  : null;

export const auth = app ? getAuth(app) : null;
const googleProvider = new GoogleAuthProvider();

export const loginWithEmail = async (email, password) => {
  if (!auth) {
    throw new Error('Firebase is not configured. Please check your .env keys.');
  }
  const credential = await signInWithEmailAndPassword(auth, email, password);
  return credential.user;
};

export const registerWithEmail = async (email, password, displayName = '') => {
  if (!auth) {
    throw new Error('Firebase is not configured. Please check your .env keys.');
  }
  const credential = await createUserWithEmailAndPassword(auth, email, password);
  if (displayName && credential.user) {
    await updateProfile(credential.user, { displayName });
  }
  return credential.user;
};

export const loginWithGoogle = async () => {
  if (!auth) {
    throw new Error('Firebase is not configured. Please check your .env keys.');
  }
  const credential = await signInWithPopup(auth, googleProvider);
  return credential.user;
};

export const logoutUser = async () => {
  if (auth) {
    await signOut(auth);
  }
};

export const resetPassword = async (email) => {
  if (!auth) {
    throw new Error('Firebase is not configured. Please check your .env keys.');
  }
  await sendPasswordResetEmail(auth, email);
};

export { onAuthStateChanged };
export default app;
