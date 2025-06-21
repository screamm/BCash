export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Serve static files
    if (path === '/' || path === '/index.html') {
      return new Response(getIndexHTML(), {
        headers: {
          'Content-Type': 'text/html',
          ...corsHeaders,
        },
      });
    }

    if (path === '/manifest.json') {
      return new Response(getManifest(), {
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders,
        },
      });
    }

    if (path === '/sw.js') {
      return new Response(getServiceWorker(), {
        headers: {
          'Content-Type': 'application/javascript',
          ...corsHeaders,
        },
      });
    }

    if (path === '/favicon.ico') {
      return new Response(getFavicon(), {
        headers: {
          'Content-Type': 'image/svg+xml',
          'Cache-Control': 'public, max-age=86400',
          ...corsHeaders,
        },
      });
    }

    // API Routes
    if (path.startsWith('/api/')) {
      try {
        let response;

        if (path === '/api/auth' && method === 'POST') {
          response = await handleAuth(request, env);
        } else if (path === '/api/balance' && method === 'GET') {
          response = await handleGetBalance(request, env);
        } else if (path === '/api/children' && method === 'GET') {
          response = await handleGetChildren(request, env);
        } else if (path === '/api/transactions' && method === 'GET') {
          response = await handleGetTransactions(request, env);
        } else if (path === '/api/transactions' && method === 'POST') {
          response = await handleAddTransaction(request, env);
        } else {
          response = new Response('Not Found', { status: 404 });
        }

        // Add CORS headers to API responses
        const newHeaders = new Headers(response.headers);
        Object.entries(corsHeaders).forEach(([key, value]) => {
          newHeaders.set(key, value);
        });

        return new Response(response.body, {
          status: response.status,
          headers: newHeaders,
        });
      } catch (error) {
        console.error('API Error:', error);
        return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders,
          },
        });
      }
    }

    return new Response('Not Found', { status: 404, headers: corsHeaders });
  },
};

// Auth handler
async function handleAuth(request, env) {
  const { username, password, userType } = await request.json();

  if (!username || !password || !userType) {
    return new Response(JSON.stringify({ success: false, error: 'Saknade fält' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Simple password verification (i produktion: använd bcrypt)
  const isValidPassword = password === '123' || password === '456';

  if (!isValidPassword) {
    return new Response(JSON.stringify({ success: false, error: 'Fel lösenord' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    let user;
    if (userType === 'child') {
      const stmt = env.DB.prepare('SELECT * FROM children WHERE username = ?');
      user = await stmt.bind(username.toLowerCase()).first();
    } else {
      const stmt = env.DB.prepare('SELECT * FROM parents WHERE username = ?');
      user = await stmt.bind(username.toLowerCase()).first();
    }

    if (user) {
      const token = await generateSimpleToken(user.id, userType);

      return new Response(
        JSON.stringify({
          success: true,
          user: {
            id: user.id,
            name: user.name,
            type: userType,
            balance: user.balance || null,
          },
          token,
        }),
        {
          headers: { 'Content-Type': 'application/json' },
        }
      );
    } else {
      return new Response(JSON.stringify({ success: false, error: 'Användare inte hittad' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  } catch (error) {
    console.error('Auth error:', error);
    return new Response(JSON.stringify({ success: false, error: 'Databasfel' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Get balance handler
async function handleGetBalance(request, env) {
  const authResult = await verifyAuth(request);
  if (!authResult.success) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (authResult.user.type === 'child') {
    const stmt = env.DB.prepare('SELECT balance FROM children WHERE id = ?');
    const result = await stmt.bind(authResult.user.id).first();

    return new Response(
      JSON.stringify({
        balance: result?.balance || 0,
      }),
      {
        headers: { 'Content-Type': 'application/json' },
      }
    );
  } else {
    return new Response(JSON.stringify({ error: 'Not allowed' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Get children handler (för föräldrar)
async function handleGetChildren(request, env) {
  const authResult = await verifyAuth(request);
  if (!authResult.success || authResult.user.type !== 'parent') {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const stmt = env.DB.prepare('SELECT id, name, balance FROM children ORDER BY name');
  const result = await stmt.all();

  return new Response(
    JSON.stringify({
      children: result.results || [],
    }),
    {
      headers: { 'Content-Type': 'application/json' },
    }
  );
}

// Get transactions handler
async function handleGetTransactions(request, env) {
  const authResult = await verifyAuth(request);
  if (!authResult.success) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  let stmt;
  if (authResult.user.type === 'child') {
    stmt = env.DB.prepare(`
      SELECT t.*, c.name as child_name 
      FROM transactions t 
      JOIN children c ON t.child_id = c.id 
      WHERE t.child_id = ? 
      ORDER BY t.created_at DESC 
      LIMIT 50
    `);
    stmt = stmt.bind(authResult.user.id);
  } else {
    stmt = env.DB.prepare(`
      SELECT t.*, c.name as child_name 
      FROM transactions t 
      JOIN children c ON t.child_id = c.id 
      ORDER BY t.created_at DESC 
      LIMIT 100
    `);
  }

  const result = await stmt.all();

  return new Response(
    JSON.stringify({
      transactions: result.results || [],
    }),
    {
      headers: { 'Content-Type': 'application/json' },
    }
  );
}

// Add transaction handler
async function handleAddTransaction(request, env) {
  const authResult = await verifyAuth(request);
  if (!authResult.success || authResult.user.type !== 'parent') {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const { childId, amount, description } = await request.json();

  if (!childId || !amount || !description) {
    return new Response(JSON.stringify({ error: 'Saknade fält' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    // Start transaction
    await env.DB.prepare('BEGIN').run();

    // Update balance
    const updateStmt = env.DB.prepare(
      'UPDATE children SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
    );
    await updateStmt.bind(amount, childId).run();

    // Add transaction record
    const insertStmt = env.DB.prepare(
      'INSERT INTO transactions (child_id, amount, description, created_by) VALUES (?, ?, ?, ?)'
    );
    await insertStmt.bind(childId, amount, description, authResult.user.id).run();

    // Commit transaction
    await env.DB.prepare('COMMIT').run();

    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    // Rollback on error
    await env.DB.prepare('ROLLBACK').run();
    console.error('Transaction error:', error);

    return new Response(JSON.stringify({ error: 'Databasfel' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Simple token generation (för demo - använd JWT i produktion)
async function generateSimpleToken(userId, userType) {
  const payload = {
    id: userId,
    type: userType,
    exp: Date.now() + 24 * 60 * 60 * 1000, // 24 timmar
  };

  return btoa(JSON.stringify(payload));
}

// Verify authentication
async function verifyAuth(request) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { success: false };
  }

  const token = authHeader.substring(7);

  try {
    const payload = JSON.parse(atob(token));

    if (payload.exp < Date.now()) {
      return { success: false };
    }

    return {
      success: true,
      user: { id: payload.id, type: payload.type },
    };
  } catch {
    return { success: false };
  }
}

// HTML content för huvudsidan
function getIndexHTML() {
  return `<!DOCTYPE html>
<html lang="sv">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sparappen - Håll koll på dina pengar</title>
    <meta name="description" content="En app för barn att hålla koll på sina sparpengar och för föräldrar att hantera barnens ekonomi">
    <link rel="manifest" href="/manifest.json">
    <link rel="icon" href="/favicon.ico" type="image/svg+xml">
    <meta name="theme-color" content="#4CAF50">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="default">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }

        .container {
            max-width: 400px;
            margin: 0 auto;
            background: white;
            min-height: 100vh;
            box-shadow: 0 0 20px rgba(0,0,0,0.3);
            position: relative;
        }

        .header {
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
            padding: 20px;
            text-align: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .header h1 {
            font-size: 24px;
            margin-bottom: 5px;
        }

        .user-info {
            font-size: 14px;
            opacity: 0.9;
        }

        .logout-btn {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            background: rgba(255,255,255,0.2);
            border: none;
            color: white;
            padding: 8px 12px;
            border-radius: 15px;
            font-size: 12px;
            cursor: pointer;
        }

        .screen {
            display: none;
            padding: 20px;
        }

        .screen.active {
            display: block;
        }

        .login-form {
            background: white;
            padding: 30px;
            border-radius: 15px;
            margin: 50px 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }

        input, select, textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e1e1;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }

        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: #4CAF50;
        }

        .btn {
            width: 100%;
            background: #4CAF50;
            color: white;
            padding: 15px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
            margin-bottom: 10px;
        }

        .btn:hover {
            background: #45a049;
        }

        .btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }

        .btn-secondary {
            background: #6c757d;
        }

        .btn-secondary:hover {
            background: #5a6268;
        }

        .balance-card {
            background: linear-gradient(135deg, #FFD700, #FFA500);
            color: white;
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }

        .balance-amount {
            font-size: 48px;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .balance-label {
            font-size: 16px;
            opacity: 0.9;
        }

        .quick-actions {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-bottom: 30px;
        }

        .quick-btn {
            padding: 20px;
            border: none;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }

        .quick-btn:active {
            transform: scale(0.95);
        }

        .btn-add {
            background: #28a745;
            color: white;
        }

        .btn-remove {
            background: #dc3545;
            color: white;
        }

        .transaction-list {
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .transaction-item {
            padding: 15px;
            border-bottom: 1px solid #f0f0f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .transaction-item:last-child {
            border-bottom: none;
        }

        .transaction-info {
            flex: 1;
        }

        .transaction-desc {
            font-weight: 600;
            margin-bottom: 5px;
        }

        .transaction-date {
            font-size: 12px;
            color: #888;
        }

        .transaction-amount {
            font-weight: bold;
            font-size: 16px;
        }

        .transaction-amount.positive {
            color: #28a745;
        }

        .transaction-amount.negative {
            color: #dc3545;
        }

        .kids-grid {
            display: grid;
            gap: 15px;
            margin-bottom: 20px;
        }

        .kid-card {
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .kid-info h3 {
            margin-bottom: 5px;
            color: #333;
        }

        .kid-balance {
            font-size: 18px;
            font-weight: bold;
            color: #4CAF50;
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
        }

        .modal.active {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 15px;
            width: 90%;
            max-width: 400px;
            max-height: 80vh;
            overflow-y: auto;
        }

        .modal-header {
            margin-bottom: 20px;
        }

        .modal-header h2 {
            margin-bottom: 10px;
        }

        .close-btn {
            float: right;
            background: none;
            border: none;
            font-size: 24px;
            cursor: pointer;
            color: #888;
        }

        .loading {
            text-align: center;
            padding: 20px;
            color: #888;
        }

        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }

        .success {
            background: #d4edda;
            color: #155724;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }

        @media (max-width: 480px) {
            .container {
                max-width: 100%;
            }
            
            .balance-amount {
                font-size: 36px;
            }
            
            .quick-actions {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Login Screen -->
        <div id="loginScreen" class="screen active">
            <div class="login-form">
                <h2 style="text-align: center; margin-bottom: 30px; color: #4CAF50;">🏦 Sparappen</h2>
                
                <div id="loginError" class="error" style="display: none;"></div>
                
                <div class="form-group">
                    <label for="userType">Jag är:</label>
                    <select id="userType">
                        <option value="child">Barn</option>
                        <option value="parent">Förälder</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="username">Användarnamn:</label>
                    <input type="text" id="username" placeholder="Skriv ditt namn">
                </div>
                
                <div class="form-group">
                    <label for="password">Lösenord:</label>
                    <input type="password" id="password" placeholder="Skriv ditt lösenord">
                </div>
                
                <button class="btn" id="loginBtn" onclick="login()">Logga in</button>
                
                <div style="text-align: center; margin-top: 20px; font-size: 12px; color: #888;">
                    <strong>Demo-användare:</strong><br>
                    Barn: anna/123, erik/123, lila/123<br>
                    Förälder: mamma/456
                </div>
            </div>
        </div>

        <!-- Child Dashboard -->
        <div id="childScreen" class="screen">
            <div class="header">
                <button class="logout-btn" onclick="logout()">Logga ut</button>
                <h1>🏦 Mina Pengar</h1>
                <div class="user-info">Inloggad som: <span id="childName"></span></div>
            </div>
            
            <div class="balance-card">
                <div class="balance-amount" id="childBalance">0 kr</div>
                <div class="balance-label">Mitt saldo</div>
            </div>
            
            <h3 style="margin-bottom: 15px;">📋 Mina transaktioner</h3>
            <div class="transaction-list" id="childTransactions">
                <div class="loading">Laddar transaktioner...</div>
            </div>
        </div>

        <!-- Parent Dashboard -->
        <div id="parentScreen" class="screen">
            <div class="header">
                <button class="logout-btn" onclick="logout()">Logga ut</button>
                <h1>👨‍👩‍👧‍👦 Föräldrapanel</h1>
                <div class="user-info">Inloggad som förälder</div>
            </div>
            
            <h3 style="margin-bottom: 15px;">Barnens saldo</h3>
            <div class="kids-grid" id="kidsGrid">
                <div class="loading">Laddar barn...</div>
            </div>
            
            <div class="quick-actions">
                <button class="quick-btn btn-add" onclick="showTransactionModal('add')">
                    💰 Lägg till pengar
                </button>
                <button class="quick-btn btn-remove" onclick="showTransactionModal('remove')">
                    💸 Ta bort pengar
                </button>
            </div>
            
            <h3 style="margin-bottom: 15px;">📋 Alla transaktioner</h3>
            <div class="transaction-list" id="parentTransactions">
                <div class="loading">Laddar transaktioner...</div>
            </div>
        </div>
    </div>

    <!-- Transaction Modal -->
    <div id="transactionModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <button class="close-btn" onclick="closeModal()">&times;</button>
                <h2 id="modalTitle">Lägg till pengar</h2>
            </div>
            
            <div id="transactionError" class="error" style="display: none;"></div>
            <div id="transactionSuccess" class="success" style="display: none;"></div>
            
            <div class="form-group">
                <label for="selectChild">Välj barn:</label>
                <select id="selectChild"></select>
            </div>
            
            <div class="form-group">
                <label for="amount">Belopp (kr):</label>
                <input type="number" id="amount" placeholder="0" min="1">
            </div>
            
            <div class="form-group">
                <label for="description">Beskrivning:</label>
                <textarea id="description" rows="3" placeholder="T.ex. Veckopeng, Köpte godis..."></textarea>
            </div>
            
            <button class="btn" id="transactionBtn" onclick="addTransaction()">Genomför</button>
            <button class="btn btn-secondary" onclick="closeModal()">Avbryt</button>
        </div>
    </div>

    <script>
        // App State
        let currentUser = null;
        let currentTransactionType = 'add';
        let authToken = null;
        
        // API Base URL
        const API_BASE = '';

        // Login Function
        async function login() {
            const userType = document.getElementById('userType').value;
            const username = document.getElementById('username').value.toLowerCase().trim();
            const password = document.getElementById('password').value;
            
            if (!username || !password) {
                showError('loginError', 'Fyll i både användarnamn och lösenord');
                return;
            }
            
            const loginBtn = document.getElementById('loginBtn');
            loginBtn.disabled = true;
            loginBtn.textContent = 'Loggar in...';
            
            try {
                const response = await fetch(API_BASE + '/api/auth', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password, userType })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    currentUser = data.user;
                    authToken = data.token;
                    hideError('loginError');
                    showDashboard();
                } else {
                    showError('loginError', data.error || 'Fel användarnamn eller lösenord');
                }
            } catch (error) {
                console.error('Login error:', error);
                showError('loginError', 'Nätverksfel. Försök igen.');
            } finally {
                loginBtn.disabled = false;
                loginBtn.textContent = 'Logga in';
            }
        }

        // Show appropriate dashboard
        function showDashboard() {
            document.getElementById('loginScreen').classList.remove('active');
            
            if (currentUser.type === 'child') {
                document.getElementById('childScreen').classList.add('active');
                updateChildDashboard();
            } else {
                document.getElementById('parentScreen').classList.add('active');
                updateParentDashboard();
            }
        }

        // Update Child Dashboard
        async function updateChildDashboard() {
            document.getElementById('childName').textContent = currentUser.name;
            document.getElementById('childBalance').textContent = (currentUser.balance || 0) + ' kr';
            
            // Load current balance
            try {
                const response = await fetch(API_BASE + '/api/balance', {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    document.getElementById('childBalance').textContent = data.balance + ' kr';
                }
            } catch (error) {
                console.error('Balance error:', error);
            }
            
            // Load transactions
            await loadTransactions('child');
        }

        // Update Parent Dashboard
        async function updateParentDashboard() {
            await loadChildren();
            await loadTransactions('parent');
        }

        // Load children for parent dashboard
        async function loadChildren() {
            try {
                const response = await fetch(API_BASE + '/api/children', {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    updateKidsGrid(data.children);
                    updateChildSelect(data.children);
                } else {
                    document.getElementById('kidsGrid').innerHTML = '<div class="error">Kunde inte ladda barn</div>';
                }
            } catch (error) {
                console.error('Load children error:', error);
                document.getElementById('kidsGrid').innerHTML = '<div class="error">Nätverksfel</div>';
            }
        }

        // Update Kids Grid
        function updateKidsGrid(children) {
            const grid = document.getElementById('kidsGrid');
            
            if (!children || children.length === 0) {
                grid.innerHTML = '<div style="padding: 20px; text-align: center; color: #888;">Inga barn registrerade</div>';
                return;
            }
            
            grid.innerHTML = children.map(child => \`
                <div class="kid-card">
                    <div class="kid-info">
                        <h3>\${child.name}</h3>
                        <div style="color: #888; font-size: 14px;">Saldo</div>
                    </div>
                    <div class="kid-balance">\${child.balance || 0} kr</div>
                </div>
            \`).join('');
        }

        // Update Child Select in modal
        function updateChildSelect(children) {
            const select = document.getElementById('selectChild');
            
            if (!children || children.length === 0) {
                select.innerHTML = '<option value="">Inga barn tillgängliga</option>';
                return;
            }
            
            select.innerHTML = children.map(child => 
                \`<option value="\${child.id}">\${child.name}</option>\`
            ).join('');
        }

        // Load transactions
        async function loadTransactions(userType) {
            const elementId = userType === 'child' ? 'childTransactions' : 'parentTransactions';
            
            try {
                const response = await fetch(API_BASE + '/api/transactions', {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    updateTransactionList(elementId, data.transactions, userType);
                } else {
                    document.getElementById(elementId).innerHTML = '<div class="error">Kunde inte ladda transaktioner</div>';
                }
            } catch (error) {
                console.error('Load transactions error:', error);
                document.getElementById(elementId).innerHTML = '<div class="error">Nätverksfel</div>';
            }
        }

        // Update Transaction List
        function updateTransactionList(elementId, transactions, userType) {
            const container = document.getElementById(elementId);
            
            if (!transactions || transactions.length === 0) {
                container.innerHTML = '<div style="padding: 30px; text-align: center; color: #888;">Inga transaktioner än</div>';
                return;
            }
            
            container.innerHTML = transactions.map(transaction => {
                const isPositive = transaction.amount > 0;
                const date = new Date(transaction.created_at).toLocaleDateString('sv-SE');
                
                return \`
                    <div class="transaction-item">
                        <div class="transaction-info">
                            <div class="transaction-desc">
                                \${userType === 'parent' && transaction.child_name ? transaction.child_name + ': ' : ''}\${transaction.description}
                            </div>
                            <div class="transaction-date">\${date}</div>
                        </div>
                        <div class="transaction-amount \${isPositive ? 'positive' : 'negative'}">
                            \${isPositive ? '+' : ''}\${transaction.amount} kr
                        </div>
                    </div>
                \`;
            }).join('');
        }

        // Show Transaction Modal
        function showTransactionModal(type) {
            currentTransactionType = type;
            document.getElementById('modalTitle').textContent = 
                type === 'add' ? 'Lägg till pengar' : 'Ta bort pengar';
            document.getElementById('transactionModal').classList.add('active');
            hideError('transactionError');
            hideSuccess('transactionSuccess');
        }

        // Close Modal
        function closeModal() {
            document.getElementById('transactionModal').classList.remove('active');
            document.getElementById('amount').value = '';
            document.getElementById('description').value = '';
            hideError('transactionError');
            hideSuccess('transactionSuccess');
        }

        // Add Transaction
        async function addTransaction() {
            const childId = parseInt(document.getElementById('selectChild').value);
            const amount = parseInt(document.getElementById('amount').value);
            const description = document.getElementById('description').value.trim();
            
            if (!childId) {
                showError('transactionError', 'Välj ett barn');
                return;
            }
            
            if (!amount || amount <= 0) {
                showError('transactionError', 'Ange ett giltigt belopp');
                return;
            }
            
            if (!description) {
                showError('transactionError', 'Lägg till en beskrivning');
                return;
            }
            
            const transactionAmount = currentTransactionType === 'add' ? amount : -amount;
            
            const transactionBtn = document.getElementById('transactionBtn');
            transactionBtn.disabled = true;
            transactionBtn.textContent = 'Genomför...';
            
            try {
                const response = await fetch(API_BASE + '/api/transactions', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({
                        childId,
                        amount: transactionAmount,
                        description
                    })
                });
                
                const data = await response.json();
                
                if (response.ok && data.success) {
                    showSuccess('transactionSuccess', \`\${transactionAmount > 0 ? 'Lade till' : 'Tog bort'} \${Math.abs(transactionAmount)} kr!\`);
                    
                    // Clear form
                    document.getElementById('amount').value = '';
                    document.getElementById('description').value = '';
                    
                    // Refresh dashboard
                    await updateParentDashboard();
                    
                    // Close modal after a delay
                    setTimeout(() => {
                        closeModal();
                    }, 1500);
                } else {
                    showError('transactionError', data.error || 'Något gick fel');
                }
            } catch (error) {
                console.error('Transaction error:', error);
                showError('transactionError', 'Nätverksfel. Försök igen.');
            } finally {
                transactionBtn.disabled = false;
                transactionBtn.textContent = 'Genomför';
            }
        }

        // Logout
        function logout() {
            currentUser = null;
            authToken = null;
            document.getElementById('childScreen').classList.remove('active');
            document.getElementById('parentScreen').classList.remove('active');
            document.getElementById('loginScreen').classList.add('active');
            
            // Clear form
            document.getElementById('username').value = '';
            document.getElementById('password').value = '';
            hideError('loginError');
        }

        // Utility Functions
        function showError(elementId, message) {
            const element = document.getElementById(elementId);
            element.textContent = message;
            element.style.display = 'block';
        }

        function hideError(elementId) {
            document.getElementById(elementId).style.display = 'none';
        }

        function showSuccess(elementId, message) {
            const element = document.getElementById(elementId);
            element.textContent = message;
            element.style.display = 'block';
        }

        function hideSuccess(elementId) {
            document.getElementById(elementId).style.display = 'none';
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            // Enable enter key for login
            document.getElementById('password').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    login();
                }
            });
            
            // Enable enter key for transaction modal
            document.getElementById('amount').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    document.getElementById('description').focus();
                }
            });
            
            document.getElementById('description').addEventListener('keypress', function(e) {
                if (e.key === 'Enter' && e.ctrlKey) {
                    addTransaction();
                }
            });

            // Register service worker for PWA
            if ('serviceWorker' in navigator) {
                navigator.serviceWorker.register('/sw.js')
                    .then(registration => console.log('SW registered'))
                    .catch(error => console.log('SW registration failed'));
            }
        });

        // PWA install prompt
        let deferredPrompt;
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
            
            // Show install button (optional)
            const installBtn = document.createElement('button');
            installBtn.textContent = '📱 Installera app';
            installBtn.className = 'btn btn-secondary';
            installBtn.style.margin = '10px 20px';
            installBtn.onclick = async () => {
                deferredPrompt.prompt();
                const { outcome } = await deferredPrompt.userChoice;
                console.log('Install outcome:', outcome);
                deferredPrompt = null;
                installBtn.remove();
            };
            
            document.querySelector('.login-form').appendChild(installBtn);
        });
    </script>
</body>
</html>`;
}

// PWA Manifest
function getManifest() {
  return JSON.stringify({
    name: 'Sparappen - Barnens sparpengar',
    short_name: 'Sparappen',
    description: 'Håll koll på barnens sparpengar enkelt och säkert',
    start_url: '/',
    display: 'standalone',
    background_color: '#667eea',
    theme_color: '#4CAF50',
    orientation: 'portrait',
    categories: ['finance', 'family', 'education'],
    icons: [
      {
        src: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 192 192'><rect width='192' height='192' fill='%234CAF50' rx='20'/><text x='96' y='120' font-size='80' text-anchor='middle' fill='white'>🏦</text></svg>",
        sizes: '192x192',
        type: 'image/svg+xml',
      },
      {
        src: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 512'><rect width='512' height='512' fill='%234CAF50' rx='50'/><text x='256' y='320' font-size='200' text-anchor='middle' fill='white'>🏦</text></svg>",
        sizes: '512x512',
        type: 'image/svg+xml',
      },
    ],
  });
}

// Service Worker
function getServiceWorker() {
  return `
const CACHE_NAME = 'sparappen-v1';
const urlsToCache = [
  '/',
  '/manifest.json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request)
      .then((response) => {
        if (response) {
          return response;
        }
        return fetch(event.request);
      }
    )
  );
});
`;
}

// Favicon
function getFavicon() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
    <rect width="32" height="32" fill="#4CAF50" rx="4"/>
    <text x="16" y="22" font-size="16" text-anchor="middle" fill="white">🏦</text>
  </svg>`;
}
