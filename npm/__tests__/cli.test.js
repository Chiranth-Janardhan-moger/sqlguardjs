const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const cliPath = path.join(__dirname, '..', 'bin', 'sqlguardjs.js');

describe('CLI scanner', () => {
  it('scans a single adversarial payload as JSON', () => {
    const output = execFileSync(process.execPath, [
      cliPath,
      'scan',
      '1 UNION/**/SELECT password FROM users--'
    ], { encoding: 'utf8' });
    const parsed = JSON.parse(output);

    expect(parsed.result.label).toBe('sqli');
    expect(parsed.result.confidence).toBeGreaterThanOrEqual(0.5);
  });

  it.each([
    ['MySQL versioned comment SQLi', 'id=-1/*!50000UNION SELECT username,password FROM users*/', 'sqli'],
    ['SVG data URI XSS', 'data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+PC9zdmc+', 'xss']
  ])('detects %s through the CLI', (_name, payload, label) => {
    const output = execFileSync(process.execPath, [
      cliPath,
      'scan',
      payload
    ], { encoding: 'utf8' });
    const parsed = JSON.parse(output);

    expect(parsed.result.label).toBe(label);
    expect(parsed.result.confidence).toBeGreaterThanOrEqual(0.5);
  });

  it('scans payload files and emits CSV', () => {
    const filePath = path.join(os.tmpdir(), `sqlguardjs-cli-${process.pid}.txt`);
    fs.writeFileSync(filePath, [
      'hello world',
      '<script>alert(1)</script>'
    ].join('\n'));

    try {
      const output = execFileSync(process.execPath, [
        cliPath,
        'scan-file',
        filePath,
        '--format',
        'csv'
      ], { encoding: 'utf8' });

      expect(output).toContain('payload,label,confidence');
      expect(output).toContain('"hello world","benign",0');
      expect(output).toMatch(/"<script>alert\(1\)<\/script>","xss",/);
    } finally {
      fs.rmSync(filePath, { force: true });
    }
  });

  it('sanitizes formula-leading payloads in CSV output', () => {
    const output = execFileSync(process.execPath, [
      cliPath,
      'scan',
      '=HYPERLINK("http://evil.test","click")',
      '--format',
      'csv'
    ], { encoding: 'utf8' });

    expect(output).toContain('payload,label,confidence');
    expect(output).toContain('"\'=HYPERLINK(""http://evil.test"",""click"")","benign",0');
  });

  it('escapes newlines in CSV output so payloads cannot forge rows', () => {
    const output = execFileSync(process.execPath, [
      cliPath,
      'scan',
      "1' OR '1'='1\nforged,benign,0",
      '--format',
      'csv'
    ], { encoding: 'utf8' });
    const rows = output.trim().split(/\r?\n/);

    expect(rows).toHaveLength(2);
    expect(rows[1]).toContain("\\nforged,benign,0");
    expect(rows[1]).not.toContain('\nforged');
  });
});
