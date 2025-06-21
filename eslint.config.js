export default [
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        // Cloudflare Workers globals
        addEventListener: 'readonly',
        fetch: 'readonly',
        Request: 'readonly',
        Response: 'readonly',
        Headers: 'readonly',
        URL: 'readonly',
        console: 'readonly',
        crypto: 'readonly',
        btoa: 'readonly',
        atob: 'readonly',
      },
    },
    rules: {
      'no-console': 'off',
      'no-unused-vars': 'warn',
    },
  },
  {
    ignores: ['node_modules/', 'dist/', '*.min.js', '.wrangler/'],
  },
];
