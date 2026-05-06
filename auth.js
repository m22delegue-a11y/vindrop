// auth.js — chargé après config.js sur toutes les pages
const sb = supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

async function login(email, password) {
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error) throw error;
  return data;
}

async function logout() {
  await sb.auth.signOut();
  location.href = 'login.html';
}

async function getProfile() {
  const { data: { user } } = await sb.auth.getUser();
  if (!user) return null;
  const { data, error } = await sb.from('profiles').select('*').eq('id', user.id).single();
  if (error) return null;
  return data;
}

// À appeler en haut de chaque page protégée. Renvoie le profil ou redirige.
async function requireAuth(allowedRoles) {
  // Politique "Se souvenir de moi" : si non coché ET nouvelle session navigateur
  // (sessionStorage vide), on déconnecte. sessionStorage est purgé à la fermeture.
  if (localStorage.getItem('vd_remember') === '0' && !sessionStorage.getItem('vd_alive')) {
    await sb.auth.signOut();
    location.href = 'login.html';
    return null;
  }
  sessionStorage.setItem('vd_alive', '1');

  const profile = await getProfile();
  if (!profile) { location.href = 'login.html'; return null; }
  if (allowedRoles && !allowedRoles.includes(profile.role)) {
    location.href = 'equipe.html';
    return null;
  }
  return profile;
}

// Admin uniquement — crée un compte employé sans casser sa session
async function createEmployee(email, password, name) {
  const temp = supabase.createClient(SUPABASE_URL, SUPABASE_KEY);
  const { data, error } = await temp.auth.signUp({
    email, password,
    options: { data: { role: 'employee', name } }
  });
  if (error) throw error;
  await temp.auth.signOut();
  return data;
}
