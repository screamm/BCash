#!/usr/bin/env node

/**
 * Sparappen Health Check & Self-Test Suite
 * Testar alla viktiga funktioner i appen
 */

import { fetch } from 'undici';

const BASE_URL = process.env.TEST_URL || 'http://localhost:8787';

console.log('🏦 Sparappen - Självtest Suite');
console.log('================================');
console.log(`Testing against: ${BASE_URL}`);
console.log('');

let testsPassed = 0;
let testsFailed = 0;

// Test helper functions
async function test(name, testFn) {
  try {
    console.log(`🧪 ${name}...`);
    await testFn();
    console.log(`✅ ${name} - PASSED`);
    testsPassed++;
  } catch (error) {
    console.log(`❌ ${name} - FAILED: ${error.message}`);
    testsFailed++;
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

  if (!response.ok && !options.expectError) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    return { ...response, data: await response.json() };
  }

  return { ...response, data: await response.text() };
}

// Test Suite
async function runTests() {
  // 1. Basic connectivity tests
  await test('Server responds to basic requests', async () => {
    const response = await fetchAPI('/');
    if (response.status !== 200) {
      throw new Error(`Expected 200, got ${response.status}`);
    }
    if (!response.data.includes('Sparappen')) {
      throw new Error('Homepage does not contain expected content');
    }
  });

  await test('Favicon is served correctly', async () => {
    const response = await fetchAPI('/favicon.ico');
    if (response.status !== 200) {
      throw new Error(`Expected 200, got ${response.status}`);
    }
    if (!response.data.includes('<svg')) {
      throw new Error('Favicon is not an SVG');
    }
  });

  await test('Manifest is served correctly', async () => {
    const response = await fetchAPI('/manifest.json');
    if (response.status !== 200) {
      throw new Error(`Expected 200, got ${response.status}`);
    }
    if (!response.data.name || !response.data.icons) {
      throw new Error('Manifest is missing required fields');
    }
  });

  // 2. Health check endpoint
  await test('Health check endpoint works', async () => {
    const response = await fetchAPI('/api/health');
    if (response.status !== 200) {
      throw new Error(`Expected 200, got ${response.status}`);
    }
    if (response.data.status !== 'healthy') {
      throw new Error(`Expected healthy status, got: ${response.data.status}`);
    }
    if (!response.data.checks.database) {
      throw new Error('Health check missing database status');
    }
  });

  // 3. Authentication tests
  let authToken = null;

  await test('Authentication fails with invalid credentials', async () => {
    const response = await fetchAPI('/api/auth', {
      method: 'POST',
      body: JSON.stringify({
        username: 'invalid',
        password: 'invalid',
        userType: 'parent',
      }),
      expectError: true,
    });
    if (response.status !== 401) {
      throw new Error(`Expected 401, got ${response.status}`);
    }
  });

  await test('Authentication succeeds with valid parent credentials', async () => {
    const response = await fetchAPI('/api/auth', {
      method: 'POST',
      body: JSON.stringify({
        username: 'mamma',
        password: 'förälder456',
        userType: 'parent',
      }),
    });
    if (response.status !== 200) {
      throw new Error(`Expected 200, got ${response.status}`);
    }
    if (!response.data.success || !response.data.token) {
      throw new Error('Authentication response missing token');
    }
    authToken = response.data.token;
  });

  await test('Authentication succeeds with valid child credentials', async () => {
    const response = await fetchAPI('/api/auth', {
      method: 'POST',
      body: JSON.stringify({
        username: 'anna',
        password: 'barn123',
        userType: 'child',
      }),
    });
    if (response.status !== 200) {
      throw new Error(`Expected 200, got ${response.status}`);
    }
    if (!response.data.success || !response.data.token) {
      throw new Error('Child authentication response missing token');
    }
  });

  // 4. Protected endpoint tests (requires parent auth)
  await test('Protected endpoints require authentication', async () => {
    const response = await fetchAPI('/api/children', {
      expectError: true,
    });
    if (response.status !== 401) {
      throw new Error(`Expected 401, got ${response.status}`);
    }
  });

  await test('Can fetch children list with valid token', async () => {
    const response = await fetchAPI('/api/children', {
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
    });
    if (response.status !== 200) {
      throw new Error(`Expected 200, got ${response.status}`);
    }
    if (!Array.isArray(response.data.children)) {
      throw new Error('Children response is not an array');
    }
  });

  await test('Can fetch transactions list with valid token', async () => {
    const response = await fetchAPI('/api/transactions', {
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
    });
    if (response.status !== 200) {
      throw new Error(`Expected 200, got ${response.status}`);
    }
    if (!Array.isArray(response.data.transactions)) {
      throw new Error('Transactions response is not an array');
    }
  });

  // 5. CRUD operations tests
  let newChildId = null;

  await test('Can create a new child', async () => {
    const response = await fetchAPI('/api/children', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        name: 'Test Barn',
        username: 'testbarn',
        password: 'testpass123',
      }),
    });
    if (response.status !== 200) {
      throw new Error(`Expected 200, got ${response.status}`);
    }
    if (!response.data.success) {
      throw new Error('Create child response indicates failure');
    }

    // Verify child was created by fetching children list
    const childrenResponse = await fetchAPI('/api/children', {
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
    });
    const testChild = childrenResponse.data.children.find((c) => c.username === 'testbarn');
    if (!testChild) {
      throw new Error('Created child not found in children list');
    }
    newChildId = testChild.id;
  });

  await test('Can update child information', async () => {
    if (!newChildId) {
      throw new Error('No child ID available for update test');
    }

    const response = await fetchAPI('/api/children', {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        id: newChildId,
        name: 'Updated Test Barn',
        username: 'updatedtestbarn',
      }),
    });
    if (response.status !== 200) {
      throw new Error(`Expected 200, got ${response.status}`);
    }
    if (!response.data.success) {
      throw new Error('Update child response indicates failure');
    }
  });

  await test('Can add transaction for child', async () => {
    if (!newChildId) {
      throw new Error('No child ID available for transaction test');
    }

    const response = await fetchAPI('/api/transactions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        childId: newChildId,
        amount: 100,
        description: 'Test transaction',
      }),
    });
    if (response.status !== 200) {
      throw new Error(`Expected 200, got ${response.status}`);
    }
    if (!response.data.success) {
      throw new Error('Add transaction response indicates failure');
    }
  });

  await test('Can soft delete child', async () => {
    if (!newChildId) {
      throw new Error('No child ID available for delete test');
    }

    const response = await fetchAPI('/api/children', {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        id: newChildId,
      }),
    });
    if (response.status !== 200) {
      throw new Error(`Expected 200, got ${response.status}`);
    }
    if (!response.data.success) {
      throw new Error('Delete child response indicates failure');
    }

    // Verify child is no longer in active children list
    const childrenResponse = await fetchAPI('/api/children', {
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
    });
    const deletedChild = childrenResponse.data.children.find((c) => c.id === newChildId);
    if (deletedChild) {
      throw new Error('Deleted child still appears in children list');
    }
  });

  // 6. Security tests
  await test('SQL injection protection works', async () => {
    const response = await fetchAPI('/api/auth', {
      method: 'POST',
      body: JSON.stringify({
        username: "admin'; DROP TABLE children; --",
        password: 'anything',
        userType: 'parent',
      }),
      expectError: true,
    });
    if (response.status !== 401) {
      throw new Error(`Expected 401, got ${response.status}`);
    }
  });

  await test('CORS headers are present', async () => {
    const response = await fetchAPI('/api/health');
    const corsHeader = response.headers.get('Access-Control-Allow-Origin');
    if (!corsHeader) {
      throw new Error('CORS headers missing');
    }
  });

  // Test summary
  console.log('🏁 Test Summary');
  console.log('===============');
  console.log(`✅ Tests passed: ${testsPassed}`);
  console.log(`❌ Tests failed: ${testsFailed}`);
  console.log(`📊 Total tests: ${testsPassed + testsFailed}`);

  if (testsFailed > 0) {
    console.log('');
    console.log('❌ Some tests failed. Please check the issues above.');
    process.exit(1);
  } else {
    console.log('');
    console.log('🎉 All tests passed! Sparappen is working correctly.');
    process.exit(0);
  }
}

// Run the tests
runTests().catch((error) => {
  console.error('💥 Test suite crashed:', error);
  process.exit(1);
});
