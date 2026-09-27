import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { createRoot } from 'react-dom/client';

// ---------------------------------------------------------------------------
// API helper. Token lives only in component state (never localStorage/sessionStorage,
// per the D13 test) — fetch's default credentials ("same-origin") already sends the
// httpOnly refresh cookie automatically, since the SPA and API share one origin.
// ---------------------------------------------------------------------------
async function api(method, path, { token, body } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const res = await fetch(`/v1${path}`, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  if (!res.ok) {
    const err = new Error(json?.error?.message || `request failed (${res.status})`);
    err.status = res.status;
    err.code = json?.error?.code;
    err.reason = json?.error?.reason;
    throw err;
  }
  return json;
}

function decodeToken(token) {
  try {
    const payload = token.split('.')[1];
    return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
  } catch {
    return null;
  }
}

function themeColor(theme) {
  const known = { cobalt: '#1e3a5f', slate: '#334155', amber: '#78350f', violet: '#4c1d95', forest: '#14532d' };
  if (known[theme]) return known[theme];
  let hash = 0;
  for (const ch of String(theme)) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
  return `hsl(${hash % 360}, 45%, 22%)`;
}

const ALL_PERMISSIONS = [
  'device:list', 'device:view', 'device:control', 'device:terminal', 'device:file_transfer', 'device:provision', 'device:update',
  'session:start', 'session:view', 'session:terminate',
  'grant:create', 'grant:revoke',
  'user:read', 'user:invite', 'user:role:update', 'user:remove',
  'audit:read',
  'org:update', 'org:delete',
];
const ALL_ROLES = ['owner', 'admin', 'operator', 'auditor', 'viewer'];

// ---------------------------------------------------------------------------
// Global styles
// ---------------------------------------------------------------------------
function GlobalStyle() {
  return (
    <style>{`
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
      * { box-sizing: border-box; }
      body { margin: 0; font-family: 'Inter', ui-sans-serif, system-ui, sans-serif; background: #eef0f4; color: #14161a; }
      button { font: inherit; cursor: pointer; border: 1px solid #d7dae1; background: #fff; border-radius: 8px; padding: 7px 14px; transition: all .15s ease; }
      button:hover { background: #f4f5f7; border-color: #c2c6cf; }
      button:active { transform: translateY(1px); }
      button.primary { background: linear-gradient(135deg, #4f46e5, #2563eb); border-color: transparent; color: #fff; font-weight: 600; box-shadow: 0 2px 8px rgba(37,99,235,.35); position: relative; overflow: hidden; }
      button.primary:hover { filter: brightness(1.08); }
      button.danger { border-color: #f2b8b5; color: #dc2626; }
      button.danger:hover { background: #fef2f2; }
      input, select { font: inherit; padding: 9px 12px; border: 1px solid #d7dae1; border-radius: 8px; outline: none; transition: border-color .15s ease, box-shadow .15s ease; }
      input:focus, select:focus { border-color: #4f46e5; box-shadow: 0 0 0 3px rgba(79,70,229,.15); }
      table { border-collapse: collapse; width: 100%; }
      th { text-align: left; padding: 10px; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: #6b7280; border-bottom: 2px solid #eceef2; }
      td { text-align: left; padding: 12px 10px; border-bottom: 1px solid #eceef2; font-size: 14px; }
      tr:hover td { background: #fafbfc; }
      .card { background: #fff; border-radius: 14px; padding: 24px; box-shadow: 0 1px 2px rgba(16,24,40,.04), 0 4px 16px rgba(16,24,40,.06); }
      .row-actions button { margin-right: 6px; font-size: 12px; padding: 5px 10px; }
      .pill { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 600; letter-spacing: .02em; background: #eef1f6; color: #475467; text-transform: uppercase; }

      @keyframes floatOrb {
        0%, 100% { transform: translate(0, 0) scale(1); }
        50% { transform: translate(40px, -50px) scale(1.1); }
      }
      .orb { position: absolute; border-radius: 50%; filter: blur(70px); pointer-events: none; animation: floatOrb 14s ease-in-out infinite; }

      @keyframes sparkBurst {
        0% { opacity: .95; transform: translate(-50%, -50%) scale(0); }
        60% { opacity: .5; }
        100% { opacity: 0; transform: translate(-50%, -50%) scale(3.2); }
      }
      .spark {
        position: absolute; top: var(--sy, 50%); left: var(--sx, 50%);
        width: 16px; height: 16px; border-radius: 50%;
        background: radial-gradient(circle, rgba(255,255,255,.95), rgba(255,255,255,0) 65%);
        animation: sparkBurst .65s ease-out forwards;
        pointer-events: none;
      }
    `}</style>
  );
}

// ---------------------------------------------------------------------------
// Login screen
// ---------------------------------------------------------------------------
function LoginScreen({ onLoggedIn, initialNotice }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [sparks, setSparks] = useState([]);

  function fireSpark(e) {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * 100;
    const y = ((e.clientY - rect.top) / rect.height) * 100;
    const id = Date.now() + Math.random();
    setSparks((s) => [...s, { id, x, y }]);
    setTimeout(() => setSparks((s) => s.filter((sp) => sp.id !== id)), 700);
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await api('POST', '/auth/login', { body: { email, password } });
      onLoggedIn(res);
    } catch (err) {
      setError({ message: err.message, code: err.code });
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={{
      position: 'relative', overflow: 'hidden',
      display: 'flex', minHeight: '100vh', alignItems: 'center', justifyContent: 'center',
      background: 'linear-gradient(160deg, #0b1120, #111827 55%, #0b1120)',
    }}>
      <div className="orb" style={{ width: 420, height: 420, top: '-10%', left: '-8%', background: '#4f46e5', animationDelay: '0s' }} />
      <div className="orb" style={{ width: 360, height: 360, bottom: '-12%', right: '-6%', background: '#2563eb', animationDelay: '3s' }} />
      <div className="orb" style={{ width: 260, height: 260, top: '55%', left: '55%', background: '#7c3aed', animationDelay: '6s', opacity: .5 }} />

      <form data-testid="login-form" onSubmit={handleSubmit} className="card" style={{ width: 380, position: 'relative', zIndex: 1 }}>
        <div style={{
          width: 44, height: 44, borderRadius: 12, marginBottom: 18,
          background: 'linear-gradient(135deg, #4f46e5, #2563eb)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: '#fff', fontWeight: 800, fontSize: 18,
        }}>R</div>
        <h1 style={{ margin: '0 0 4px', fontSize: 24, fontWeight: 800, letterSpacing: '-0.02em' }}>RemoteOps</h1>
        <p style={{ margin: '0 0 24px', color: '#6b7280', fontSize: 14 }}>Sign in to manage your organizations.</p>
        {initialNotice && (
          <p style={{ color: '#166534', fontSize: 13, background: '#f0fdf4', padding: '8px 12px', borderRadius: 8, marginBottom: 16 }}>
            {initialNotice}
          </p>
        )}
        <label style={{ display: 'block', fontSize: 13, fontWeight: 600, marginBottom: 6 }}>Email</label>
        <input
          data-testid="login-email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@company.com"
          style={{ width: '100%', marginBottom: 16 }}
        />
        <label style={{ display: 'block', fontSize: 13, fontWeight: 600, marginBottom: 6 }}>Password</label>
        <input
          data-testid="login-password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="••••••••"
          style={{ width: '100%', marginBottom: 20 }}
        />
        {error && (
          <div data-testid="login-error" data-error-code={error.code} role="alert" style={{
            color: '#dc2626', fontSize: 13, marginBottom: 16, background: '#fef2f2', padding: '10px 12px', borderRadius: 8,
          }}>
            {error.message}
          </div>
        )}
        <button
          data-testid="login-submit"
          type="submit"
          className="primary"
          disabled={busy}
          onClick={fireSpark}
          style={{ width: '100%', padding: '11px 14px', fontSize: 15 }}
        >
          {sparks.map((s) => (
            <span key={s.id} className="spark" style={{ '--sx': `${s.x}%`, '--sy': `${s.y}%` }} />
          ))}
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Invite acceptance screen — /invite/:token
// ---------------------------------------------------------------------------
function InviteScreen({ token, onDone }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');

  useEffect(() => {
    api('GET', `/invites/${token}`)
      .then(setInvite)
      .catch((err) => setError(err.message));
  }, [token]);

  async function handleSubmit(e) {
    e.preventDefault();
    try {
      await api('POST', `/invites/${token}/accept`, { body: { name, password } });
      onDone();
    } catch (err) {
      setError(err.message);
    }
  }

  if (error) {
    return (
      <main style={{ display: 'flex', minHeight: '100vh', alignItems: 'center', justifyContent: 'center' }}>
        <div data-testid="invite-error" className="card" style={{ color: '#dc2626' }}>{error}</div>
      </main>
    );
  }
  if (!invite) return null;

  return (
    <main style={{ display: 'flex', minHeight: '100vh', alignItems: 'center', justifyContent: 'center' }}>
      <form onSubmit={handleSubmit} className="card" style={{ width: 340 }}>
        <h1 style={{ marginTop: 0, fontSize: 20 }}>Join {invite.orgName}</h1>
        <p style={{ fontSize: 13 }}>Role: <span data-testid="invite-role">{invite.role}</span></p>
        <label style={{ display: 'block', fontSize: 13, marginBottom: 4 }}>Email</label>
        <input data-testid="invite-email" value={invite.email} readOnly style={{ width: '100%', marginBottom: 12 }} />
        <label style={{ display: 'block', fontSize: 13, marginBottom: 4 }}>Your name</label>
        <input data-testid="invite-name" value={name} onChange={(e) => setName(e.target.value)} style={{ width: '100%', marginBottom: 12 }} />
        <label style={{ display: 'block', fontSize: 13, marginBottom: 4 }}>Choose a password</label>
        <input data-testid="invite-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} style={{ width: '100%', marginBottom: 16 }} />
        <button data-testid="invite-submit" type="submit" className="primary" style={{ width: '100%' }}>Join</button>
      </form>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Devices card
// ---------------------------------------------------------------------------
function DevicesCard({ token, orgId, orgPermissions, refreshKey }) {
  const [devices, setDevices] = useState(null);

  const load = useCallback(() => {
    api('GET', `/orgs/${orgId}/devices`, { token }).then((r) => setDevices(r.devices));
  }, [token, orgId]);

  useEffect(() => { load(); }, [load, refreshKey]);

  async function addDevice() {
    const name = window.prompt('Device name?');
    if (!name) return;
    const kind = window.prompt('Kind (macos/windows/linux/android/ios)?', 'linux');
    if (!kind) return;
    await api('POST', `/orgs/${orgId}/devices`, { token, body: { name, kind } });
    load();
  }

  async function startSession(deviceId, mode) {
    try {
      await api('POST', `/orgs/${orgId}/sessions`, { token, body: { deviceId, mode } });
      alert(`${mode} session started.`);
    } catch (err) {
      alert(`Could not start session: ${err.message}`);
    }
  }

  async function renameDevice(d) {
    const name = window.prompt('New name?', d.name);
    if (!name) return;
    await api('PATCH', `/orgs/${orgId}/devices/${d.id}`, { token, body: { name } });
    load();
  }

  async function decommission(d) {
    if (!window.confirm(`Decommission ${d.name}?`)) return;
    await api('DELETE', `/orgs/${orgId}/devices/${d.id}`, { token });
    load();
  }

  if (devices === null) return <div className="card">Loading…</div>;

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h2 style={{ margin: 0, fontSize: 18 }}>Devices</h2>
        {orgPermissions['device:provision']?.effect === 'allow' && (
          <button data-testid="add-device" data-permission="device:provision" data-state="unlocked" onClick={addDevice}>+ Add device</button>
        )}
      </div>
      {devices.length === 0 && <div data-testid="devices-empty">No devices yet.</div>}
      {devices.length > 0 && (
        <table>
          <thead><tr><th>Name</th><th>Kind</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody>
            {devices.map((d) => {
              const p = d.permissions;
              return (
                <tr key={d.id} data-testid="device-row" data-device-id={d.id}>
                  <td>{d.name}</td>
                  <td>{d.kind}</td>
                  <td><span className="pill">{d.online ? 'online' : 'offline'}</span></td>
                  <td className="row-actions">
                    {p['device:view']?.effect === 'allow' && (
                      <button data-testid="start-view" data-permission="device:view" data-state="unlocked" onClick={() => startSession(d.id, 'view')}>View</button>
                    )}
                    {p['device:control']?.effect === 'allow' && (
                      <button data-testid="start-control" data-permission="device:control" data-state="unlocked" onClick={() => startSession(d.id, 'control')}>Control</button>
                    )}
                    {p['device:terminal']?.effect === 'allow' && (
                      <button data-testid="start-terminal" data-permission="device:terminal" data-state="unlocked" onClick={() => startSession(d.id, 'terminal')}>Terminal</button>
                    )}
                    {p['device:file_transfer']?.effect === 'allow' && (
                      <button data-testid="transfer-files" data-permission="device:file_transfer" data-state="unlocked" onClick={() => alert('File transfer UI not built for this pass.')}>Files</button>
                    )}
                    {p['device:update']?.effect === 'allow' && (
                      <button data-testid="rename-device" data-permission="device:update" data-state="unlocked" onClick={() => renameDevice(d)}>Rename</button>
                    )}
                    {p['device:provision']?.effect === 'allow' && (
                      <button data-testid="decommission-device" data-permission="device:provision" data-state="unlocked" className="danger" onClick={() => decommission(d)}>Decommission</button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// People card
// ---------------------------------------------------------------------------
function PeopleCard({ token, orgId, orgPermissions }) {
  const [members, setMembers] = useState(null);

  const load = useCallback(() => {
    api('GET', `/orgs/${orgId}/members`, { token }).then((r) => setMembers(r.members));
  }, [token, orgId]);

  useEffect(() => { load(); }, [load]);

  async function invite() {
    const email = window.prompt('Invite email?');
    if (!email) return;
    const role = window.prompt(`Role (${ALL_ROLES.join('/')})?`, 'viewer');
    if (!role) return;
    const res = await api('POST', `/orgs/${orgId}/invites`, { token, body: { email, role } });
    alert(`Invite link: ${window.location.origin}/invite/${res.inviteToken}`);
    load();
  }

  async function changeRole(m) {
    const role = window.prompt(`New role for ${m.email} (${ALL_ROLES.join('/')})?`, m.role);
    if (!role || role === m.role) return;
    try {
      await api('PATCH', `/orgs/${orgId}/members/${m.user_id}`, { token, body: { role } });
      load();
    } catch (err) {
      alert(err.message);
    }
  }

  async function toggleSuspend(m) {
    try {
      if (m.status === 'suspended') {
        await api('DELETE', `/orgs/${orgId}/members/${m.user_id}/suspend`, { token });
      } else {
        await api('POST', `/orgs/${orgId}/members/${m.user_id}/suspend`, { token });
      }
      load();
    } catch (err) {
      alert(err.message);
    }
  }

  async function removeMember(m) {
    if (!window.confirm(`Remove ${m.email}?`)) return;
    try {
      await api('DELETE', `/orgs/${orgId}/members/${m.user_id}`, { token });
      load();
    } catch (err) {
      alert(err.message);
    }
  }

  if (members === null) return <div className="card">Loading…</div>;

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h2 style={{ margin: 0, fontSize: 18 }}>People</h2>
        {orgPermissions['user:invite']?.effect === 'allow' && (
          <button data-testid="invite-user" data-permission="user:invite" data-state="unlocked" onClick={invite}>+ Invite</button>
        )}
      </div>
      <table>
        <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
          {members.map((m) => (
            <tr key={m.user_id} data-testid="user-row" data-user-id={m.user_id}>
              <td>{m.name}</td>
              <td>{m.email}</td>
              <td>{m.role}</td>
              <td><span className="pill">{m.status}</span></td>
              <td className="row-actions">
                {orgPermissions['user:role:update']?.effect === 'allow' && (
                  <button data-testid="role-select" data-permission="user:role:update" data-state="unlocked" onClick={() => changeRole(m)}>Change role</button>
                )}
                {orgPermissions['user:remove']?.effect === 'allow' && (
                  <>
                    <button data-testid="suspend-user" data-permission="user:remove" data-state="unlocked" onClick={() => toggleSuspend(m)}>
                      {m.status === 'suspended' ? 'Reinstate' : 'Suspend'}
                    </button>
                    <button data-testid="remove-user" data-permission="user:remove" data-state="unlocked" className="danger" onClick={() => removeMember(m)}>Remove</button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Grants card
// ---------------------------------------------------------------------------
function GrantsCard({ token, orgId, orgPermissions }) {
  const [grants, setGrants] = useState(null);
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [formUser, setFormUser] = useState('');
  const [formDevice, setFormDevice] = useState('');
  const [formEffect, setFormEffect] = useState('allow');
  const [formPerms, setFormPerms] = useState([]);

  const load = useCallback(() => {
    api('GET', `/orgs/${orgId}/grants`, { token }).then((r) => setGrants(r.grants));
  }, [token, orgId]);

  useEffect(() => { load(); }, [load]);

  async function openForm() {
    const [m, d] = await Promise.all([
      api('GET', `/orgs/${orgId}/members`, { token }),
      api('GET', `/orgs/${orgId}/devices`, { token }),
    ]);
    setMembers(m.members);
    setDevices(d.devices);
    setShowForm(true);
  }

  function togglePerm(key) {
    setFormPerms((prev) => (prev.includes(key) ? prev.filter((p) => p !== key) : [...prev, key]));
  }

  async function submitGrant() {
    try {
      await api('POST', `/orgs/${orgId}/grants`, {
        token,
        body: { userId: formUser, deviceId: formDevice || null, effect: formEffect, permissions: formPerms },
      });
      setShowForm(false);
      setFormPerms([]);
      load();
    } catch (err) {
      alert(err.message);
    }
  }

  async function revoke(g) {
    if (!window.confirm('Revoke this grant?')) return;
    await api('DELETE', `/orgs/${orgId}/grants/${g.id}`, { token });
    load();
  }

  if (grants === null) return <div className="card">Loading…</div>;

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h2 style={{ margin: 0, fontSize: 18 }}>Grants</h2>
        {orgPermissions['grant:create']?.effect === 'allow' && (
          <button data-testid="new-grant" data-permission="grant:create" data-state="unlocked" onClick={openForm}>+ New grant</button>
        )}
      </div>

      {showForm && (
        <div style={{ border: '1px solid #e5e7eb', borderRadius: 8, padding: 12, marginBottom: 12 }}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
            <select data-testid="grant-user" value={formUser} onChange={(e) => setFormUser(e.target.value)}>
              <option value="">Select user…</option>
              {members.map((m) => <option key={m.user_id} value={m.user_id}>{m.email}</option>)}
            </select>
            <select data-testid="grant-device" value={formDevice} onChange={(e) => setFormDevice(e.target.value)}>
              <option value="">Org-wide</option>
              {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select>
            <select data-testid="grant-effect" value={formEffect} onChange={(e) => setFormEffect(e.target.value)}>
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
            </select>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 8 }}>
            {ALL_PERMISSIONS.map((key) => (
              <label key={key} style={{ fontSize: 12 }}>
                <input type="checkbox" data-permission-key={key} checked={formPerms.includes(key)} onChange={() => togglePerm(key)} /> {key}
              </label>
            ))}
          </div>
          <button data-testid="grant-submit" className="primary" onClick={submitGrant}>Create grant</button>
          <button onClick={() => setShowForm(false)} style={{ marginLeft: 8 }}>Cancel</button>
        </div>
      )}

      <table>
        <thead><tr><th>User</th><th>Device</th><th>Effect</th><th>Permissions</th><th></th></tr></thead>
        <tbody>
          {grants.map((g) => (
            <tr key={g.id} data-testid="grant-row" data-effect={g.effect}>
              <td>{g.user_id}</td>
              <td>{g.device_id || 'org-wide'}</td>
              <td><span className="pill">{g.effect}</span></td>
              <td style={{ fontSize: 12 }}>{g.permissions.join(', ')}</td>
              <td>
                {orgPermissions['grant:revoke']?.effect === 'allow' && (
                  <button data-testid="revoke-grant" data-permission="grant:revoke" data-state="unlocked" className="danger" onClick={() => revoke(g)}>Revoke</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sessions card
// ---------------------------------------------------------------------------
function SessionsCard({ token, orgId, orgPermissions, currentUserId }) {
  const [sessions, setSessions] = useState(null);
  const [devices, setDevices] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [formDevice, setFormDevice] = useState('');
  const [formMode, setFormMode] = useState('view');

  const load = useCallback(() => {
    api('GET', `/orgs/${orgId}/sessions`, { token }).then((r) => setSessions(r.sessions));
  }, [token, orgId]);

  useEffect(() => { load(); }, [load]);

  async function openForm() {
    const d = await api('GET', `/orgs/${orgId}/devices`, { token });
    setDevices(d.devices);
    setShowForm(true);
  }

  async function submit() {
    try {
      await api('POST', `/orgs/${orgId}/sessions`, { token, body: { deviceId: formDevice, mode: formMode } });
      setShowForm(false);
      load();
    } catch (err) {
      alert(err.message);
    }
  }

  async function stop(s) {
    await api('DELETE', `/sessions/${s.id}`, { token });
    load();
  }

  if (sessions === null) return <div className="card">Loading…</div>;

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h2 style={{ margin: 0, fontSize: 18 }}>Sessions</h2>
        {orgPermissions['session:start']?.effect === 'allow' && (
          <button data-testid="new-session" data-permission="session:start" data-state="unlocked" onClick={openForm}>+ Start session</button>
        )}
      </div>
      {showForm && (
        <div style={{ border: '1px solid #e5e7eb', borderRadius: 8, padding: 12, marginBottom: 12 }}>
          <select value={formDevice} onChange={(e) => setFormDevice(e.target.value)} style={{ marginRight: 8 }}>
            <option value="">Select device…</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
          <select value={formMode} onChange={(e) => setFormMode(e.target.value)} style={{ marginRight: 8 }}>
            <option value="view">View</option>
            <option value="control">Control</option>
            <option value="terminal">Terminal</option>
          </select>
          <button className="primary" onClick={submit}>Start</button>
          <button onClick={() => setShowForm(false)} style={{ marginLeft: 8 }}>Cancel</button>
        </div>
      )}
      <table>
        <thead><tr><th>Device</th><th>Mode</th><th>State</th><th></th></tr></thead>
        <tbody>
          {sessions.map((s) => {
            const isOwn = s.user_id === currentUserId;
            const canStop = isOwn || orgPermissions['session:terminate']?.effect === 'allow';
            return (
              <tr key={s.id} data-testid="session-row" data-session-id={s.id}>
                <td>{s.device_id}</td>
                <td>{s.mode}</td>
                <td><span className="pill">{s.state}</span></td>
                <td>
                  {s.state === 'active' && canStop && (
                    <button data-testid="stop-session" onClick={() => stop(s)}>Stop</button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Audit card
// ---------------------------------------------------------------------------
function AuditCard({ token, orgId }) {
  const [events, setEvents] = useState(null);

  useEffect(() => {
    api('GET', `/orgs/${orgId}/audit`, { token }).then((r) => setEvents(r.events));
  }, [token, orgId]);

  if (events === null) return <div className="card">Loading…</div>;

  return (
    <div className="card">
      <h2 style={{ margin: '0 0 12px', fontSize: 18 }}>Audit log</h2>
      <table>
        <thead><tr><th>Action</th><th>Result</th><th>Reason</th><th>When</th></tr></thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id} data-testid="audit-row">
              <td>{e.action}</td>
              <td><span className="pill">{e.result}</span></td>
              <td style={{ fontSize: 12 }}>{e.reason_code || '—'}</td>
              <td style={{ fontSize: 12 }}>{new Date(e.at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Admin card
// ---------------------------------------------------------------------------
function AdminCard({ token, orgId, orgPermissions, onOrgUpdated }) {
  async function rename() {
    const name = window.prompt('New org name?');
    if (!name) return;
    await api('PATCH', `/orgs/${orgId}`, { token, body: { name } });
    onOrgUpdated();
  }
  async function del() {
    if (!window.confirm('Delete this organization? This cannot be undone.')) return;
    await api('DELETE', `/orgs/${orgId}`, { token });
    onOrgUpdated();
  }
  return (
    <div className="card">
      <h2 style={{ margin: '0 0 12px', fontSize: 18 }}>Admin</h2>
      <div className="row-actions">
        {orgPermissions['org:update']?.effect === 'allow' && (
          <button data-testid="rename-org" data-permission="org:update" data-state="unlocked" onClick={rename}>Rename org</button>
        )}
        {orgPermissions['org:delete']?.effect === 'allow' && (
          <button data-testid="delete-org" data-permission="org:delete" data-state="unlocked" className="danger" onClick={del}>Delete org</button>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// App shell
// ---------------------------------------------------------------------------
const NAV = [
  { key: 'devices', label: 'Devices', perm: ['device:list'] },
  { key: 'people', label: 'People', perm: ['user:read'] },
  { key: 'grants', label: 'Grants', perm: ['user:read'] },
  { key: 'sessions', label: 'Sessions', perm: ['session:view'] },
  { key: 'audit', label: 'Audit', perm: ['audit:read'] },
  { key: 'admin', label: 'Admin', perm: ['org:update', 'org:delete'] },
];

function AppShell({ auth, onLogout }) {
  const [token, setToken] = useState(auth.token);
  const [orgId, setOrgId] = useState(auth.orgId);
  const [role, setRole] = useState(auth.role);
  const [orgs, setOrgs] = useState(auth.orgs);
  const [permissions, setPermissions] = useState(auth.permissions);
  const [active, setActive] = useState('devices');
  const [deviceRefreshKey, setDeviceRefreshKey] = useState(0);

  const currentUserId = useMemo(() => decodeToken(token)?.sub, [token]);
  const activeOrg = orgs.find((o) => o.id === orgId) || { theme: 'slate' };

  const refreshMe = useCallback(async (tok) => {
    const me = await api('GET', '/auth/me', { token: tok });
    setOrgs(me.orgs);
    setPermissions(me.permissions);
    setRole(me.role);
  }, []);

  async function switchOrg(id) {
    if (id === orgId) return;
    const res = await api('POST', '/auth/token', { token, body: { orgId: id } });
    setToken(res.token);
    setOrgId(res.orgId);
    setRole(res.role);
    await refreshMe(res.token);
    setActive('devices');
  }

  async function createOrg() {
    const name = window.prompt('New organization name?');
    if (!name) return;
    const created = await api('POST', '/orgs', { token, body: { name } });
    const tokRes = await api('POST', '/auth/token', { token, body: { orgId: created.id } });
    setToken(tokRes.token);
    setOrgId(tokRes.orgId);
    setRole(tokRes.role);
    await refreshMe(tokRes.token);
    setActive('devices');
  }

  async function handleOrgUpdated() {
    try {
      await refreshMe(token);
    } catch {
      onLogout();
    }
  }

  useEffect(() => { setDeviceRefreshKey((k) => k + 1); }, [active]);

  const visibleNav = NAV.filter((n) => n.perm.some((p) => permissions[p]?.effect === 'allow'));

  return (
    <div data-testid="app-shell" data-org-id={orgId} data-org-theme={activeOrg.theme} style={{ minHeight: '100vh', backgroundColor: themeColor(activeOrg.theme) }}>
      <header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '18px 28px', color: '#fff', backdropFilter: 'blur(6px)', background: 'rgba(255,255,255,0.06)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <strong>RemoteOps</strong>
          <div style={{ display: 'flex', gap: 6 }}>
            {orgs.map((o) => (
              <button
                key={o.id}
                data-testid="org-option"
                data-org-id={o.id}
                onClick={() => switchOrg(o.id)}
                style={{ opacity: o.id === orgId ? 1 : 0.6, fontWeight: o.id === orgId ? 700 : 400 }}
              >
                {o.name}
              </button>
            ))}
            <button data-testid="create-org" onClick={createOrg}>+ New org</button>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span className="pill" data-testid="active-role">{role}</span>
          <button onClick={onLogout}>Sign out</button>
        </div>
      </header>

      <nav style={{ display: 'flex', gap: 8, padding: '0 24px 16px' }}>
        {visibleNav.map((n) => (
          <button
            key={n.key}
            data-testid={`nav-${n.key}`}
            onClick={() => setActive(n.key)}
            style={{ fontWeight: active === n.key ? 700 : 400 }}
          >
            {n.label}
          </button>
        ))}
      </nav>

      <main style={{ padding: '0 24px 40px' }}>
        {active === 'devices' && <DevicesCard token={token} orgId={orgId} orgPermissions={permissions} refreshKey={deviceRefreshKey} />}
        {active === 'people' && <PeopleCard token={token} orgId={orgId} orgPermissions={permissions} />}
        {active === 'grants' && <GrantsCard token={token} orgId={orgId} orgPermissions={permissions} />}
        {active === 'sessions' && <SessionsCard token={token} orgId={orgId} orgPermissions={permissions} currentUserId={currentUserId} />}
        {active === 'audit' && <AuditCard token={token} orgId={orgId} />}
        {active === 'admin' && <AdminCard token={token} orgId={orgId} orgPermissions={permissions} onOrgUpdated={handleOrgUpdated} />}
      </main>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------
function Root() {
  const [auth, setAuth] = useState(null);
  const [checkedRefresh, setCheckedRefresh] = useState(false);
  const [notice, setNotice] = useState(null);
  const path = window.location.pathname;

  useEffect(() => {
    if (path.startsWith('/invite/')) { setCheckedRefresh(true); return; }
    api('POST', '/auth/refresh')
      .then(async (res) => {
        const me = await api('GET', '/auth/me', { token: res.token });
        setAuth({ token: res.token, orgId: res.orgId, role: res.role, orgs: me.orgs, permissions: me.permissions });
      })
      .catch(() => {})
      .finally(() => setCheckedRefresh(true));
  }, []);

  async function handleLoggedIn(loginRes) {
    const me = await api('GET', '/auth/me', { token: loginRes.token });
    setAuth({ token: loginRes.token, orgId: loginRes.orgId, role: loginRes.role, orgs: me.orgs, permissions: me.permissions });
  }

  if (path.startsWith('/invite/')) {
    const token = path.slice('/invite/'.length);
    return (
      <InviteScreen
        token={token}
        onDone={() => { window.history.replaceState({}, '', '/'); setNotice('Account created — sign in to continue.'); window.location.reload(); }}
      />
    );
  }

  if (!checkedRefresh) return null;
  if (!auth) return <LoginScreen onLoggedIn={handleLoggedIn} initialNotice={notice} />;
  return <AppShell auth={auth} onLogout={() => setAuth(null)} />;
}

createRoot(document.getElementById('root')).render(
  <>
    <GlobalStyle />
    <Root />
  </>
);