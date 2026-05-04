// supabase/functions/update_user/index.ts
// Edge Function: met à jour email + password d'un user via auth.admin
// Sécurité : vérifie que l'appelant est un admin avant d'agir.

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.0'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SERVICE_KEY  = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
const ANON_KEY     = Deno.env.get('SUPABASE_ANON_KEY')!

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS'
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  })
}

Deno.serve(async (req) => {
  // CORS preflight
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
  if (req.method !== 'POST')   return json({ error: 'Method not allowed' }, 405)

  try {
    // ====== 1. Vérifier l'appelant ======
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) return json({ error: 'Missing authorization header' }, 401)

    // Client "user" : reçoit le JWT pour identifier qui appelle
    const userClient = createClient(SUPABASE_URL, ANON_KEY, {
      global: { headers: { Authorization: authHeader } }
    })
    const { data: { user }, error: userErr } = await userClient.auth.getUser()
    if (userErr || !user) return json({ error: 'Unauthorized' }, 401)

    // Client "admin" : service_role, bypasse RLS
    const adminClient = createClient(SUPABASE_URL, SERVICE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false }
    })

    // L'appelant a-t-il role='admin' dans profiles ?
    const { data: caller, error: callerErr } = await adminClient
      .from('profiles').select('role').eq('id', user.id).single()
    if (callerErr || !caller || caller.role !== 'admin') {
      return json({ error: 'Forbidden — admin only' }, 403)
    }

    // ====== 2. Lire & valider le body ======
    const { user_id, email, password } = await req.json().catch(() => ({}))
    if (!user_id) return json({ error: 'user_id required' }, 400)

    const updates: { email?: string; password?: string } = {}
    if (typeof email === 'string' && email.trim()) updates.email = email.trim()
    if (typeof password === 'string' && password.length > 0) {
      if (password.length < 6) return json({ error: 'Password too short (min 6)' }, 400)
      updates.password = password
    }
    if (Object.keys(updates).length === 0) {
      return json({ success: true, message: 'Nothing to update' })
    }

    // ====== 3. La cible doit aussi être un employé (pas un autre admin par sécurité) ======
    const { data: target, error: tErr } = await adminClient
      .from('profiles').select('role').eq('id', user_id).single()
    if (tErr || !target) return json({ error: 'Target user not found' }, 404)
    // Optionnel : restreindre aux employés. Commente ces 2 lignes si admin doit pouvoir
    // modifier d'autres admins.
    if (target.role !== 'employee') {
      return json({ error: 'Can only edit employees' }, 403)
    }

    // ====== 4. Update via auth.admin ======
    const { data, error } = await adminClient.auth.admin.updateUserById(user_id, updates)
    if (error) return json({ error: error.message }, 400)

    // Sync de l'email dans profiles (le trigger ne se déclenche pas sur update)
    if (updates.email) {
      await adminClient.from('profiles').update({ email: updates.email }).eq('id', user_id)
    }

    return json({
      success: true,
      user: { id: data.user.id, email: data.user.email }
    })
  } catch (e) {
    return json({ error: (e as Error).message || 'Internal error' }, 500)
  }
})
