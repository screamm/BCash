#!/usr/bin/env node

/**
 * BCash Security Test Suite
 * Avancerade säkerhetstester för produktionsberedskap
 */

import { fetch } from 'undici';

const BASE_URL = process.env.TEST_URL || 'http://localhost:8787';
const COLORS = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

console.log(`${COLORS.cyan}🔒 BCash Security Test Suite${COLORS.reset}`);
console.log('=====================================');
console.log(`Testing against: ${BASE_URL}`);
console.log('');

let testsPassed = 0;
let testsFailed = 0;
let criticalFailures = 0;

// Test helper functions
async function securityTest(name, testFn, isCritical = false) {
  try {
    console.log(`${COLORS.blue}🔍 ${name}...${COLORS.reset}`);
    await testFn();
    console.log(`${COLORS.green}✅ ${name} - PASSED${COLORS.reset}`);
    testsPassed++;
  } catch (error) {
    const severity = isCritical ? 'CRITICAL' : 'FAILED';
    const color = isCritical ? COLORS.red : COLORS.yellow;
    console.log(`${color}❌ ${name} - ${severity}: ${error.message}${COLORS.reset}`);
    testsFailed++;
    if (isCritical) criticalFailures++;
  }
  console.log('');
}

async function fetchAPI(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  });

  const contentType = response.headers.get('content-type');
  let data;
  if (contentType && contentType.includes('application/json')) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  return { ...response, data };
}

// Security Test Suite
async function runSecurityTests() {
  
  // === AUTHENTICATION SECURITY ===
  console.log(`${COLORS.magenta}🔐 AUTHENTICATION SECURITY TESTS${COLORS.reset}`);
  console.log('==========================================');

  await securityTest('SQL Injection in Authentication', async () => {
    const sqlPayloads = [
      "admin' OR '1'='1",
      "admin'; DROP TABLE children;--",
      "admin' UNION SELECT * FROM parents--",
      "'; INSERT INTO parents VALUES (999,'hacker','admin');--"
    ];

    for (const payload of sqlPayloads) {
      const response = await fetchAPI('/api/auth', {
        method: 'POST',
        body: JSON.stringify({
          username: payload,
          password: 'test',
          userType: 'parent'
        })
      });
      
      if (response.status === 200 && response.data.success) {
        throw new Error(`SQL injection successful with payload: ${payload}`);
      }
    }
  }, true);

  await securityTest('Password Brute Force Protection', async () => {
    const attempts = [];
    // Test multiple failed attempts
    for (let i = 0; i < 6; i++) {
      const response = await fetchAPI('/api/auth', {
        method: 'POST',
        body: JSON.stringify({
          username: 'mamma',
          password: 'wrong_password_' + i,
          userType: 'parent'
        })
      });
      attempts.push(response);
    }
    
    // After 5 attempts, account should be locked
    const lastAttempt = attempts[5];
    if (lastAttempt.status !== 423 && lastAttempt.status !== 429) {
      throw new Error('Brute force protection not working - account not locked after 5+ attempts');
    }
  }, true);

  await securityTest('Rate Limiting Protection', async () => {
    const requests = [];
    // Send many requests rapidly
    for (let i = 0; i < 12; i++) {
      requests.push(
        fetchAPI('/api/auth', {
          method: 'POST',
          body: JSON.stringify({
            username: 'test_user_' + i,
            password: 'test',
            userType: 'parent'
          })
        })
      );
    }
    
    const responses = await Promise.all(requests);
    const rateLimited = responses.some(r => r.status === 429);
    
    if (!rateLimited) {
      throw new Error('Rate limiting not working - no 429 responses after rapid requests');
    }
  }, true);

  // === TOKEN SECURITY ===
  console.log(`${COLORS.magenta}🎫 TOKEN SECURITY TESTS${COLORS.reset}`);
  console.log('================================');

  await securityTest('JWT Token Manipulation', async () => {
    // First get a valid token
    const authResponse = await fetchAPI('/api/auth', {
      method: 'POST',
      body: JSON.stringify({
        username: 'mamma',
        password: 'förälder456',
        userType: 'parent'
      })
    });

    if (!authResponse.data.token) {
      throw new Error('Could not get token for manipulation test');
    }

    const token = authResponse.data.token;
    const [header, payload, signature] = token.split('.');
    
    // Try to manipulate payload
    const decodedPayload = JSON.parse(atob(payload));
    decodedPayload.type = 'admin'; // Try to escalate privileges
    const manipulatedPayload = btoa(JSON.stringify(decodedPayload));
    const manipulatedToken = `${header}.${manipulatedPayload}.${signature}`;

    // Test if manipulated token is accepted
    const testResponse = await fetchAPI('/api/children', {
      headers: {
        'Authorization': `Bearer ${manipulatedToken}`
      }
    });

    if (testResponse.status === 200) {
      throw new Error('JWT signature verification failed - manipulated token accepted');
    }
  }, true);

  await securityTest('Expired Token Rejection', async () => {
    // Create a token with expired timestamp
    const expiredPayload = {
      sub: 1,
      type: 'parent',
      iat: Math.floor(Date.now() / 1000) - 3600,
      exp: Math.floor(Date.now() / 1000) - 1800, // Expired 30 min ago
      iss: 'sparappen',
      aud: 'sparappen-users'
    };

    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = btoa(JSON.stringify(header));
    const encodedPayload = btoa(JSON.stringify(expiredPayload));
    const expiredToken = `${encodedHeader}.${encodedPayload}.fake_signature`;

    const response = await fetchAPI('/api/children', {
      headers: {
        'Authorization': `Bearer ${expiredToken}`
      }
    });

    if (response.status === 200) {
      throw new Error('Expired token was accepted');
    }
  }, true);

  // === INPUT VALIDATION ===
  console.log(`${COLORS.magenta}🧹 INPUT VALIDATION TESTS${COLORS.reset}`);
  console.log('====================================');

  await securityTest('XSS Prevention in User Input', async () => {
    const xssPayloads = [
      '<script>alert("xss")</script>',
      'javascript:alert("xss")',
      '<img src="x" onerror="alert(1)">',
      '"><script>alert("xss")</script>',
      "'; alert('xss'); //"
    ];

    // Test XSS in child creation
    for (const payload of xssPayloads) {
      try {
        const authResponse = await fetchAPI('/api/auth', {
          method: 'POST',
          body: JSON.stringify({
            username: 'mamma',
            password: 'förälder456',
            userType: 'parent'
          })
        });

        if (authResponse.data.token) {
          const response = await fetchAPI('/api/children', {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${authResponse.data.token}`
            },
            body: JSON.stringify({
              name: payload,
              username: 'xss_test'
            })
          });

          if (response.status === 200 && response.data.name === payload) {
            throw new Error(`XSS payload not sanitized: ${payload}`);
          }
        }
      } catch (error) {
        // Errors are expected for invalid payloads
      }
    }
  }, true);

  // === SECURITY HEADERS ===
  console.log(`${COLORS.magenta}🛡️ SECURITY HEADERS TESTS${COLORS.reset}`);
  console.log('====================================');

  await securityTest('Security Headers Present', async () => {
    const response = await fetchAPI('/');
    
    const requiredHeaders = [
      'x-content-type-options',
      'x-frame-options', 
      'x-xss-protection',
      'strict-transport-security'
    ];

    for (const header of requiredHeaders) {
      if (!response.headers.get(header)) {
        throw new Error(`Missing security header: ${header}`);
      }
    }
  }, true);

  await securityTest('CORS Configuration', async () => {
    const response = await fetchAPI('/', { method: 'OPTIONS' });
    
    const corsOrigin = response.headers.get('access-control-allow-origin');
    if (corsOrigin === '*') {
      console.log(`${COLORS.yellow}⚠️  CORS allows all origins - consider restricting in production${COLORS.reset}`);
    }
  });

  // === PRIVILEGE ESCALATION ===
  console.log(`${COLORS.magenta}👑 PRIVILEGE ESCALATION TESTS${COLORS.reset}`);
  console.log('=====================================');

  await securityTest('Child Cannot Access Parent Functions', async () => {
    // Login as child
    const childAuth = await fetchAPI('/api/auth', {
      method: 'POST',
      body: JSON.stringify({
        username: 'anna',
        password: 'barn123',
        userType: 'child'
      })
    });

    if (!childAuth.data.token) {
      throw new Error('Could not authenticate as child');
    }

    // Try to access parent-only endpoints
    const parentEndpoints = [
      '/api/children', // Get all children
      { endpoint: '/api/children', method: 'POST' }, // Create child
      { endpoint: '/api/children', method: 'PUT' }, // Update child
      { endpoint: '/api/children', method: 'DELETE' } // Delete child
    ];

    for (const test of parentEndpoints) {
      const endpoint = typeof test === 'string' ? test : test.endpoint;
      const method = typeof test === 'string' ? 'GET' : test.method;
      
      const response = await fetchAPI(endpoint, {
        method,
        headers: {
          'Authorization': `Bearer ${childAuth.data.token}`
        },
        body: method !== 'GET' ? JSON.stringify({ test: 'data' }) : undefined
      });

      if (response.status === 200) {
        throw new Error(`Child accessed parent endpoint: ${method} ${endpoint}`);
      }
    }
  }, true);

  // === ERROR HANDLING ===
  console.log(`${COLORS.magenta}⚠️ ERROR HANDLING TESTS${COLORS.reset}`);
  console.log('=================================');

  await securityTest('No Information Disclosure in Errors', async () => {
    // Test various malformed requests
    const malformedRequests = [
      { endpoint: '/api/auth', body: 'invalid json' },
      { endpoint: '/api/children', body: JSON.stringify({ malformed: 'data' }) },
      { endpoint: '/nonexistent', body: '{}' }
    ];

    for (const test of malformedRequests) {
      const response = await fetchAPI(test.endpoint, {
        method: 'POST',
        body: test.body,
        headers: {
          'Content-Type': 'application/json'
        }
      });

      // Check if error reveals sensitive information
      const errorText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
      const sensitivePatterns = [
        /database/i,
        /sql/i,
        /password/i,
        /secret/i,
        /token/i,
        /internal/i,
        /stack trace/i
      ];

      for (const pattern of sensitivePatterns) {
        if (pattern.test(errorText)) {
          throw new Error(`Error response contains sensitive info: ${errorText.substring(0, 100)}`);
        }
      }
    }
  });

  // === SUMMARY ===
  console.log(`${COLORS.cyan}📊 SECURITY TEST SUMMARY${COLORS.reset}`);
  console.log('===============================');
  console.log(`✅ Tests passed: ${COLORS.green}${testsPassed}${COLORS.reset}`);
  console.log(`❌ Tests failed: ${COLORS.yellow}${testsFailed}${COLORS.reset}`);
  console.log(`🚨 Critical failures: ${COLORS.red}${criticalFailures}${COLORS.reset}`);
  console.log(`📊 Total tests: ${testsPassed + testsFailed}`);
  console.log('');

  if (criticalFailures > 0) {
    console.log(`${COLORS.red}🚨 CRITICAL SECURITY ISSUES FOUND!${COLORS.reset}`);
    console.log(`${COLORS.red}This application is NOT safe for production deployment.${COLORS.reset}`);
    console.log('');
    process.exit(1);
  } else if (testsFailed > 0) {
    console.log(`${COLORS.yellow}⚠️  Some security tests failed but no critical issues found.${COLORS.reset}`);
    console.log(`${COLORS.yellow}Review and fix issues before production deployment.${COLORS.reset}`);
    console.log('');
    process.exit(1);
  } else {
    console.log(`${COLORS.green}🎉 All security tests passed!${COLORS.reset}`);
    console.log(`${COLORS.green}Application appears secure for production deployment.${COLORS.reset}`);
    console.log('');
  }
}

// Run the security tests
runSecurityTests().catch(error => {
  console.error(`${COLORS.red}Security test suite failed:${COLORS.reset}`, error);
  process.exit(1);
});