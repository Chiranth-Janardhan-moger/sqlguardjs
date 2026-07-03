const pkg = require('../package.json');

describe('package metadata', () => {
  it('should declare the runtime actually required by the CLI and middleware', () => {
    expect(pkg.engines.node).toBe('>=18.0.0');
  });

  it('should publish under the clean sqlguard package name', () => {
    expect(pkg.name).toBe('sqlguardjs');
    expect(pkg.version).toBe('1.0.0');
    expect(pkg.bin.sqlguard).toBe('bin/sqlguard.js');
  });

  it('should publish runtime files only', () => {
    expect(pkg.files).toEqual(['bin', 'src', '__tests__', 'examples', 'index.d.ts']);
  });

  it('should expose TypeScript definitions and optional Express peer metadata', () => {
    expect(pkg.types).toBe('index.d.ts');
    expect(pkg.peerDependencies.express).toBe('>=4.18.0 || >=5.0.0');
    expect(pkg.peerDependenciesMeta.express.optional).toBe(true);
  });
});
