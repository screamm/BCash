import * as Sentry from '@sentry/cloudflare';
import bcrypt from 'bcryptjs';

export default {
  async fetch(request, env, ctx) {
    // Initialize Sentry for monitoring (if available)
    try {
      if (env.SENTRY_DSN && Sentry.init) {
        Sentry.init({
          dsn: env.SENTRY_DSN,
          environment: env.ENVIRONMENT || 'production',
          tracesSampleRate: env.ENVIRONMENT === 'development' ? 1.0 : 0.1,
        });
      }
    } catch (sentryError) {
      console.warn('Sentry initialization failed:', sentryError);
    }

    // Handle request with optional Sentry error tracking
    try {
      return await handleRequest(request, env, ctx);
    } catch (error) {
      // Try to log to Sentry if available
      try {
        if (env.SENTRY_DSN && Sentry.captureException) {
          Sentry.captureException(error);
        }
      } catch (sentryError) {
        console.warn('Sentry error reporting failed:', sentryError);
      }
      
      console.error('Unhandled error:', error);
      return new Response(
        JSON.stringify({ 
          error: 'Ett systemfel inträffade. Vänligen försök igen senare.',
          requestId: crypto.randomUUID()
        }), 
        {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
  },
};

async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // Enhanced CORS headers
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
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
      } else if (path === '/api/children' && method === 'POST') {
        response = await handleCreateChild(request, env);
      } else if (path === '/api/children' && method === 'PUT') {
        response = await handleUpdateChild(request, env);
      } else if (path === '/api/children' && method === 'DELETE') {
        response = await handleDeleteChild(request, env);
              } else if (path === '/api/health' && method === 'GET') {
          response = await handleHealthCheck(request, env);
        } else if (path === '/api/gdpr/export' && method === 'POST') {
          response = await handleGDPRDataExport(request, env);
        } else if (path === '/api/gdpr/delete' && method === 'POST') {
          response = await handleGDPRDataDeletion(request, env);
        } else if (path === '/api/gdpr/consent' && method === 'POST') {
          response = await handleGDPRConsent(request, env);
        } else if (path === '/api/gdpr/privacy-policy' && method === 'GET') {
          response = await handlePrivacyPolicy(request, env);
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
}

// Auth handler with improved security
async function handleAuth(request, env) {
  const { username, password, userType } = await request.json();
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const userAgent = request.headers.get('User-Agent') || 'unknown';

  // Input validation
  if (!username || !password || !userType) {
    await logAuthAttempt(
      env,
      username || 'unknown',
      userType || 'unknown',
      false,
      clientIP,
      userAgent
    );
    return new Response(JSON.stringify({ success: false, error: 'Saknade fält' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Sanitize input
  const cleanUsername = await sanitizeInput(username);
  const cleanUserType = await sanitizeInput(userType);

  // Rate limiting check
  const rateLimitResult = await checkRateLimit(env, clientIP);
  if (!rateLimitResult.allowed) {
    return new Response(
      JSON.stringify({ 
        success: false, 
        error: 'För många inloggningsförsök. Försök igen senare.',
        retryAfter: rateLimitResult.retryAfter 
      }),
      {
        status: 429,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  try {
    let user;
    if (cleanUserType === 'child') {
      const stmt = env.DB.prepare('SELECT * FROM children WHERE username = ? AND is_active = 1');
      user = await stmt.bind(cleanUsername).first();
    } else {
      const stmt = env.DB.prepare('SELECT * FROM parents WHERE username = ? AND is_active = 1');
      user = await stmt.bind(cleanUsername).first();
    }

    if (!user) {
      await logAuthAttempt(env, cleanUsername, cleanUserType, false, clientIP, userAgent);
      return new Response(
        JSON.stringify({ success: false, error: 'Fel användarnamn eller lösenord' }),
        {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    // Check if account is locked (for parents)
    if (cleanUserType === 'parent' && user.locked_until && new Date(user.locked_until) > new Date()) {
      await logAuthAttempt(env, cleanUsername, cleanUserType, false, clientIP, userAgent);
      return new Response(
        JSON.stringify({
          success: false,
          error: 'Kontot är tillfälligt låst. Försök igen senare.',
        }),
        {
          status: 423,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    // Verify password using proper bcrypt comparison
    const isValidPassword = await verifyPassword(password, user.password);

    if (!isValidPassword) {
      // Increment failed attempts for parents
      if (cleanUserType === 'parent') {
        const failedAttempts = (user.failed_login_attempts || 0) + 1;
        let lockUntil = null;

        if (failedAttempts >= 5) {
          lockUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // Lock for 15 minutes
        }

        await env.DB.prepare(
          'UPDATE parents SET failed_login_attempts = ?, locked_until = ? WHERE id = ?'
        )
          .bind(failedAttempts, lockUntil, user.id)
          .run();
      }

      await logAuthAttempt(env, cleanUsername, cleanUserType, false, clientIP, userAgent);
      return new Response(
        JSON.stringify({ success: false, error: 'Fel användarnamn eller lösenord' }),
        {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    // Reset failed attempts on successful login
    if (cleanUserType === 'parent' && user.failed_login_attempts > 0) {
      await env.DB.prepare('UPDATE parents SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?')
        .bind(user.id)
        .run();
    }

    // Generate secure JWT token
    const token = await generateSecureToken(user.id, cleanUserType, env);

    // Log successful authentication
    await logAuthAttempt(env, cleanUsername, cleanUserType, true, clientIP, userAgent);

    return new Response(
      JSON.stringify({
        success: true,
        token,
        user: { id: user.id, name: user.name, type: cleanUserType },
      }),
      {
        headers: { 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    console.error('Auth error:', error);
    await logAuthAttempt(env, cleanUsername, cleanUserType, false, clientIP, userAgent);
    return new Response(
      JSON.stringify({ success: false, error: 'Serverfel' }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }
}

// Log authentication attempts
async function logAuthAttempt(env, username, userType, success, ipAddress, userAgent) {
  try {
    await env.DB.prepare(
      'INSERT INTO auth_logs (username, user_type, success, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)'
    )
      .bind(username, userType, success ? 1 : 0, ipAddress, userAgent)
      .run();
  } catch (error) {
    console.error('Failed to log auth attempt:', error);
  }
}

// Enhanced security functions
async function sanitizeInput(input) {
  if (!input || typeof input !== 'string') return '';
  
  // Remove potentially dangerous characters and limit length
  return input
    .replace(/[<>'"]/g, '') // Remove XSS chars
    .replace(/[;\-\-]/g, '') // Remove SQL injection chars  
    .substring(0, 100) // Limit length
    .trim();
}

async function checkRateLimit(env, clientIP) {
  const windowSize = 15 * 60 * 1000; // 15 minutes
  const maxAttempts = 10;

  try {
    // Get current attempts count (simplified - in production use Redis/KV)
    const stmt = env.DB.prepare(`
      SELECT COUNT(*) as attempts 
      FROM auth_logs 
      WHERE ip_address = ? 
      AND created_at > datetime('now', '-15 minutes')
      AND success = 0
    `);
    const result = await stmt.bind(clientIP).first();
    
    if (result.attempts >= maxAttempts) {
      return { 
        allowed: false, 
        retryAfter: windowSize / 1000 
      };
    }
    
    return { allowed: true };
  } catch (error) {
    console.error('Rate limit check failed:', error);
    return { allowed: true }; // Fail open for availability
  }
}

async function verifyPassword(plainPassword, hashedPassword) {
  try {
    // Check if it's a bcrypt hash
    if (hashedPassword.startsWith('$2b$') || hashedPassword.startsWith('$2a$')) {
      return await bcrypt.compare(plainPassword, hashedPassword);
    }
    
    // Legacy SHA-256 hashes (will be migrated to bcrypt)
    const expectedHash = await hashPasswordLegacy(plainPassword);
    const isLegacyMatch = expectedHash === hashedPassword;
    
    // If legacy hash matches, upgrade to bcrypt
    if (isLegacyMatch) {
      console.log('Legacy password detected - should be upgraded to bcrypt');
      // In production, trigger password upgrade here
    }
    
    return isLegacyMatch;
  } catch (error) {
    Sentry.captureException(error);
    console.error('Password verification failed:', error);
    return false;
  }
}

async function hashPassword(password, rounds = 12) {
  try {
    // Use bcrypt for new password hashes
    return await bcrypt.hash(password, rounds);
  } catch (error) {
    Sentry.captureException(error);
    console.error('Password hashing failed:', error);
    throw error;
  }
}

// Legacy hash function (for backward compatibility)
async function hashPasswordLegacy(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + 'sparappen_salt_2025');
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function generateSecureToken(userId, userType, env) {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  
  const payload = {
    sub: userId,
    type: userType,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60), // 24 hours
    iss: 'sparappen',
    aud: 'sparappen-users'
  };
  
  const encodedHeader = btoa(JSON.stringify(header));
  const encodedPayload = btoa(JSON.stringify(payload));
  const message = `${encodedHeader}.${encodedPayload}`;
  
  // Use a secret from environment or generate one
  const secret = env.JWT_SECRET || 'fallback-secret-change-in-production';
  const signature = await signMessage(message, secret);
  
  return `${message}.${signature}`;
}

async function signMessage(message, secret) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(message);
  
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, messageData);
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function verifySecureToken(token, env) {
  try {
    const [encodedHeader, encodedPayload, signature] = token.split('.');
    if (!encodedHeader || !encodedPayload || !signature) {
      return { valid: false };
    }
    
    const message = `${encodedHeader}.${encodedPayload}`;
    const secret = env.JWT_SECRET || 'fallback-secret-change-in-production';
    const expectedSignature = await signMessage(message, secret);
    
    if (signature !== expectedSignature) {
      return { valid: false };
    }
    
    const payload = JSON.parse(atob(encodedPayload));
    
    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return { valid: false };
    }
    
    return {
      valid: true,
      payload
    };
  } catch (error) {
    console.error('Token verification failed:', error);
    return { valid: false };
  }
}

// Get balance handler
async function handleGetBalance(request, env) {
  const authResult = await verifyAuth(request, env);
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
  const authResult = await verifyAuth(request, env);
  if (!authResult.success || authResult.user.type !== 'parent') {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const stmt = env.DB.prepare(
    'SELECT id, name, username, balance FROM children WHERE is_active = 1 ORDER BY name'
  );
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
  const authResult = await verifyAuth(request, env);
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
  const authResult = await verifyAuth(request, env);
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

// Old simple token function removed - now using secure JWT tokens

// Create child handler
async function handleCreateChild(request, env) {
  const authResult = await verifyAuth(request, env);
  if (!authResult.success || authResult.user.type !== 'parent') {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const { name, username, password } = await request.json();

  if (!name || !username || !password) {
    return new Response(JSON.stringify({ error: 'Alla fält måste fyllas i' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (password.length < 6) {
    return new Response(JSON.stringify({ error: 'Lösenordet måste vara minst 6 tecken' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    // Hash password (simplified - in production use proper bcrypt)
    const hashedPassword = await hashPassword(password);

    const stmt = env.DB.prepare('INSERT INTO children (name, username, password) VALUES (?, ?, ?)');
    await stmt.bind(name, username.toLowerCase(), hashedPassword).run();

    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    if (error.message.includes('UNIQUE constraint failed')) {
      return new Response(JSON.stringify({ error: 'Användarnamn är redan taget' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    console.error('Create child error:', error);
    return new Response(JSON.stringify({ error: 'Databasfel' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Update child handler
async function handleUpdateChild(request, env) {
  const authResult = await verifyAuth(request, env);
  if (!authResult.success || authResult.user.type !== 'parent') {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const { id, name, username } = await request.json();

  if (!id || !name || !username) {
    return new Response(JSON.stringify({ error: 'Alla fält måste fyllas i' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const stmt = env.DB.prepare(
      'UPDATE children SET name = ?, username = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND is_active = 1'
    );
    const result = await stmt.bind(name, username.toLowerCase(), id).run();

    if (result.changes === 0) {
      return new Response(JSON.stringify({ error: 'Barn inte hittat' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    if (error.message.includes('UNIQUE constraint failed')) {
      return new Response(JSON.stringify({ error: 'Användarnamn är redan taget' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    console.error('Update child error:', error);
    return new Response(JSON.stringify({ error: 'Databasfel' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Delete child handler
async function handleDeleteChild(request, env) {
  const authResult = await verifyAuth(request, env);
  if (!authResult.success || authResult.user.type !== 'parent') {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const { id } = await request.json();

  if (!id) {
    return new Response(JSON.stringify({ error: 'Barn-ID måste anges' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    // Soft delete - mark as inactive instead of actual deletion
    const stmt = env.DB.prepare(
      'UPDATE children SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
    );
    const result = await stmt.bind(id).run();

    if (result.changes === 0) {
      return new Response(JSON.stringify({ error: 'Barn inte hittat' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Delete child error:', error);
    return new Response(JSON.stringify({ error: 'Databasfel' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Health check handler
async function handleHealthCheck(request, env) {
  const results = {
    timestamp: new Date().toISOString(),
    status: 'healthy',
    checks: {},
  };

  try {
    // Database connectivity test
    const dbTest = await env.DB.prepare('SELECT 1 as test').first();
    results.checks.database = dbTest ? 'healthy' : 'unhealthy';

    // Children table test
    const childrenCount = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM children WHERE is_active = 1'
    ).first();
    results.checks.children_table = childrenCount ? 'healthy' : 'unhealthy';

    // Parents table test
    const parentsCount = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM parents WHERE is_active = 1'
    ).first();
    results.checks.parents_table = parentsCount ? 'healthy' : 'unhealthy';

    // Transactions table test
    const transactionsCount = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM transactions'
    ).first();
    results.checks.transactions_table = transactionsCount !== null ? 'healthy' : 'unhealthy';

    // Overall status
    const allHealthy = Object.values(results.checks).every((status) => status === 'healthy');
    results.status = allHealthy ? 'healthy' : 'unhealthy';

    // Log health check
    await env.DB.prepare('INSERT INTO health_checks (check_type, status, details) VALUES (?, ?, ?)')
      .bind('full_system', results.status, JSON.stringify(results.checks))
      .run();

    return new Response(JSON.stringify(results), {
      status: allHealthy ? 200 : 503,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Health check error:', error);
    Sentry.captureException(error);
    results.status = 'unhealthy';
    results.error = error.message;

    return new Response(JSON.stringify(results), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// ============================================================================
// GDPR COMPLIANCE HANDLERS
// ============================================================================

// GDPR Data Export Handler - Article 20 (Right to data portability)
async function handleGDPRDataExport(request, env) {
  const authResult = await verifyAuth(request, env);
  if (!authResult.success) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const userId = authResult.user.id;
    const userType = authResult.user.type;
    
    let userData = {};
    
    if (userType === 'child') {
      // Export child data
      const childData = await env.DB.prepare(
        'SELECT id, name, username, balance, created_at, updated_at FROM children WHERE id = ? AND is_active = 1'
      ).bind(userId).first();
      
      const transactions = await env.DB.prepare(
        'SELECT id, amount, description, type, created_at FROM transactions WHERE child_id = ? ORDER BY created_at DESC'
      ).bind(userId).all();
      
      userData = {
        profile: childData,
        transactions: transactions.results,
        export_date: new Date().toISOString(),
        export_type: 'child_data'
      };
      
    } else if (userType === 'parent') {
      // Export parent data and all children data
      const parentData = await env.DB.prepare(
        'SELECT id, name, username, created_at FROM parents WHERE id = ? AND is_active = 1'
      ).bind(userId).first();
      
      const children = await env.DB.prepare(
        'SELECT id, name, username, balance, created_at, updated_at FROM children WHERE is_active = 1'
      ).all();
      
      const allTransactions = await env.DB.prepare(
        'SELECT t.*, c.name as child_name FROM transactions t JOIN children c ON t.child_id = c.id ORDER BY t.created_at DESC'
      ).all();
      
      userData = {
        profile: parentData,
        children: children.results,
        transactions: allTransactions.results,
        export_date: new Date().toISOString(),
        export_type: 'parent_data'
      };
    }
    
    // Log GDPR export request
    await env.DB.prepare(
      'INSERT INTO audit_logs (user_id, user_type, action, resource_type, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(
      userId,
      userType,
      'gdpr_data_export',
      'user_data',
      request.headers.get('CF-Connecting-IP') || 'unknown',
      request.headers.get('User-Agent') || 'unknown'
    ).run();
    
    return new Response(JSON.stringify({
      success: true,
      data: userData,
      message: 'Dina data har exporterats enligt GDPR Artikel 20'
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="bcash-data-export-${userId}-${new Date().toISOString().split('T')[0]}.json"`
      },
    });
    
  } catch (error) {
    console.error('GDPR export error:', error);
    Sentry.captureException(error);
    return new Response(JSON.stringify({ error: 'Export misslyckades' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// GDPR Data Deletion Handler - Article 17 (Right to erasure/"Right to be forgotten")
async function handleGDPRDataDeletion(request, env) {
  const authResult = await verifyAuth(request, env);
  if (!authResult.success) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const { confirmation } = await request.json();
  
  if (confirmation !== 'JAG VILL TA BORT ALLA MINA DATA PERMANENT') {
    return new Response(JSON.stringify({ 
      error: 'Bekräftelse krävs. Skriv exakt: "JAG VILL TA BORT ALLA MINA DATA PERMANENT"' 
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const userId = authResult.user.id;
    const userType = authResult.user.type;
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userAgent = request.headers.get('User-Agent') || 'unknown';
    
    // Log deletion request before deleting
    await env.DB.prepare(
      'INSERT INTO audit_logs (user_id, user_type, action, resource_type, ip_address, user_agent, new_values) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      userId,
      userType,
      'gdpr_data_deletion_request',
      'user_data',
      clientIP,
      userAgent,
      JSON.stringify({ confirmation, timestamp: new Date().toISOString() })
    ).run();
    
    if (userType === 'child') {
      // Delete child data
      await env.DB.prepare('DELETE FROM transactions WHERE child_id = ?').bind(userId).run();
      await env.DB.prepare('DELETE FROM children WHERE id = ?').bind(userId).run();
      
    } else if (userType === 'parent') {
      // Delete parent and all associated children data
      const children = await env.DB.prepare('SELECT id FROM children').all();
      
      for (const child of children.results) {
        await env.DB.prepare('DELETE FROM transactions WHERE child_id = ?').bind(child.id).run();
      }
      
      await env.DB.prepare('DELETE FROM children').run();
      await env.DB.prepare('DELETE FROM parents WHERE id = ?').bind(userId).run();
    }
    
    // Clean up auth logs for this user (keep audit trail for legal purposes)
    await env.DB.prepare('DELETE FROM auth_logs WHERE username = ?').bind(authResult.user.username).run();
    
    return new Response(JSON.stringify({
      success: true,
      message: 'Alla dina data har tagits bort permanent enligt GDPR Artikel 17. Kontot är nu stängt.'
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
    
  } catch (error) {
    console.error('GDPR deletion error:', error);
    Sentry.captureException(error);
    return new Response(JSON.stringify({ error: 'Borttagning misslyckades' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// GDPR Consent Management Handler - Article 7 (Conditions for consent)
async function handleGDPRConsent(request, env) {
  const { userId, userType, consents } = await request.json();
  
  if (!userId || !userType || !consents) {
    return new Response(JSON.stringify({ error: 'Saknade fält för samtycke' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const consentData = {
      userId,
      userType,
      consents,
      timestamp: new Date().toISOString(),
      ip_address: request.headers.get('CF-Connecting-IP') || 'unknown',
      user_agent: request.headers.get('User-Agent') || 'unknown'
    };
    
    // Store consent in audit logs
    await env.DB.prepare(
      'INSERT INTO audit_logs (user_id, user_type, action, resource_type, new_values, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      userId,
      userType,
      'gdpr_consent_updated',
      'consent_data',
      JSON.stringify(consentData),
      consentData.ip_address,
      consentData.user_agent
    ).run();
    
    return new Response(JSON.stringify({
      success: true,
      message: 'Samtycken har uppdaterats',
      consents: consents
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
    
  } catch (error) {
    console.error('GDPR consent error:', error);
    Sentry.captureException(error);
    return new Response(JSON.stringify({ error: 'Samtycke kunde inte uppdateras' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Privacy Policy Handler
async function handlePrivacyPolicy(request, env) {
  const privacyPolicy = {
    version: "1.0",
    effective_date: "2025-01-01",
    language: "sv",
    policy: {
      data_controller: {
        name: "BCash Sparappen",
        contact: "privacy@bcash.se",
        address: "Sverige"
      },
      data_processed: [
        "Barnens namn och användarnamn",
        "Föräldrars namn och användarnamn",
        "Transaktionsdata och saldo",
        "IP-adresser i säkerhetsloggar",
        "Teknisk data för appfunktionalitet"
      ],
      legal_basis: [
        "Avtal (Art. 6.1.b) - För att tillhandahålla spartjänsten",
        "Berättigade intressen (Art. 6.1.f) - För säkerhet och bedrägeriförebyggande"
      ],
      retention_period: "Data behålls så länge kontot är aktivt + 3 år för säkerhetsloggar",
      your_rights: [
        "Rätt till tillgång (Art. 15)",
        "Rätt till rättelse (Art. 16)", 
        "Rätt till radering (Art. 17)",
        "Rätt till dataportabilitet (Art. 20)",
        "Rätt att invända (Art. 21)"
      ],
      data_sharing: "Data delas inte med tredje part förutom Cloudflare (vår tekniska leverantör)",
      security_measures: [
        "Krypterade lösenord med bcrypt",
        "HTTPS för all kommunikation",
        "Säkra JWT tokens",
        "Rate limiting och brute force-skydd",
        "Regelbunden säkerhetsövervakning"
      ]
    }
  };
  
  return new Response(JSON.stringify(privacyPolicy), {
    headers: { 
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=86400' // Cache for 24 hours
    },
  });
}

// Legacy hashPassword function removed - now using bcrypt

// Verify authentication with secure JWT
async function verifyAuth(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { success: false };
  }

  const token = authHeader.substring(7);
  const verification = await verifySecureToken(token, env);
  
  if (!verification.valid) {
    return { success: false };
  }

  return {
    success: true,
    user: { 
      id: verification.payload.sub, 
      type: verification.payload.type 
    },
  };
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
            background-attachment: fixed;
            min-height: 100vh;
            color: #333;
            overflow-x: hidden;
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
            padding: 25px 20px;
            text-align: center;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
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
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
            padding: 16px;
            border: none;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 10px;
            box-shadow: 0 4px 15px rgba(76, 175, 80, 0.3);
            position: relative;
            overflow: hidden;
        }

        .btn:hover {
            background: linear-gradient(135deg, #45a049, #4CAF50);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(76, 175, 80, 0.4);
        }

        .btn:active {
            transform: translateY(0);
            box-shadow: 0 2px 10px rgba(76, 175, 80, 0.3);
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
            padding: 35px 30px;
            border-radius: 20px;
            text-align: center;
            margin-bottom: 25px;
            box-shadow: 0 15px 35px rgba(255, 165, 0, 0.3);
            position: relative;
            overflow: hidden;
        }

        .balance-card::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: shimmer 3s ease-in-out infinite;
        }

        @keyframes shimmer {
            0%, 100% { transform: rotate(0deg); }
            50% { transform: rotate(180deg); }
        }

        .balance-amount {
            font-size: 52px;
            font-weight: 800;
            margin-bottom: 8px;
            position: relative;
            z-index: 1;
            text-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }

        .balance-label {
            font-size: 18px;
            opacity: 0.95;
            font-weight: 500;
            position: relative;
            z-index: 1;
        }

        .quick-actions {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-bottom: 30px;
        }

        .quick-btn {
            padding: 25px 20px;
            border: none;
            border-radius: 16px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 6px 20px rgba(0,0,0,0.1);
            position: relative;
            overflow: hidden;
        }

        .quick-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }

        .quick-btn:active {
            transform: translateY(-1px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }

        .btn-add {
            background: linear-gradient(135deg, #28a745, #20c997);
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
                
                <div style="text-align: center; margin-top: 20px; font-size: 14px; color: #666;">
                    <p style="margin-bottom: 10px;">Välkommen till BCash Sparappen!</p>
                    <p style="font-size: 12px; color: #888;">En säker plats för barnens sparpengar</p>
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
            const username = document.getElementById('username').value.trim();
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
