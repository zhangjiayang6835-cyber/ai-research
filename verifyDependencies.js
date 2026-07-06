const { execSync } = require('child_process');
const pkg = require('./package.json');

// Check that all internal scoped packages are only resolved from private registry
const internalScopes = Object.keys(pkg.dependencies || {})
  .filter(dep => dep.startsWith('@mycompany/'))
  .map(dep => dep.split('/')[0]);

const uniqueScopes = [...new Set(internalScopes)];

uniqueScopes.forEach(scope => {
  const registry = execSync(`npm config get ${scope}:registry`).toString().trim();
  if (!registry.startsWith('https://private-registry.mycompany.com')) {
    console.error(`ERROR: Scope ${scope} is not configured to use private registry`);
    process.exit(1);
  }
});

console.log('All internal dependencies are properly scoped to private registry.');