// CardVault Auth — PIN + Biometrics (Face ID / Touch ID)

const Auth = (() => {
  const HASH_KEY = 'cv_pin_hash';
  const BIO_KEY = 'cv_bio_enabled';
  const SESSION_KEY = 'cv_session';
  const SESSION_TTL = 15 * 60 * 1000; // 15 min

  async function hashPin(pin) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('cv_salt_' + pin));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function hasPin() { return !!localStorage.getItem(HASH_KEY); }
  function bioEnabled() { return localStorage.getItem(BIO_KEY) === '1'; }

  function sessionValid() {
    const s = localStorage.getItem(SESSION_KEY);
    if (!s) return false;
    return Date.now() - parseInt(s) < SESSION_TTL;
  }
  function startSession() { localStorage.setItem(SESSION_KEY, Date.now().toString()); }
  function clearSession() { localStorage.removeItem(SESSION_KEY); }

  async function setPin(pin) {
    localStorage.setItem(HASH_KEY, await hashPin(pin));
  }

  async function checkPin(pin) {
    const stored = localStorage.getItem(HASH_KEY);
    return stored === await hashPin(pin);
  }

  // Biometric via WebAuthn (Face ID / Touch ID)
  async function biometricAvailable() {
    try {
      if (!window.PublicKeyCredential) return false;
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch { return false; }
  }

  async function registerBiometric() {
    try {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { name: 'CardVault' },
          user: { id: new Uint8Array(16), name: 'user', displayName: 'CardVault User' },
          pubKeyCredParams: [{ alg: -7, type: 'public-key' }, { alg: -257, type: 'public-key' }],
          authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' },
          timeout: 60000,
        }
      });
      localStorage.setItem('cv_cred_id', btoa(String.fromCharCode(...new Uint8Array(cred.rawId))));
      localStorage.setItem(BIO_KEY, '1');
      return true;
    } catch (e) {
      console.warn('Biometric register failed:', e);
      return false;
    }
  }

  async function authenticateBiometric() {
    try {
      const credIdStr = localStorage.getItem('cv_cred_id');
      if (!credIdStr) return false;
      const credId = Uint8Array.from(atob(credIdStr), c => c.charCodeAt(0));
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      await navigator.credentials.get({
        publicKey: {
          challenge,
          allowCredentials: [{ id: credId, type: 'public-key' }],
          userVerification: 'required',
          timeout: 60000,
        }
      });
      return true;
    } catch (e) {
      console.warn('Biometric auth failed:', e);
      return false;
    }
  }

  return { hasPin, bioEnabled, sessionValid, startSession, clearSession, setPin, checkPin, biometricAvailable, registerBiometric, authenticateBiometric };
})();
