const { evaluatePayloads } = require('../src/detector');

const corpus = [
  { payload: 'hello world', label: 'benign' },
  { payload: 'Please select a report from the menu', label: 'benign' },
  { payload: "O'Brien profile update", label: 'benign' },
  { payload: 'javascript is disabled in this browser', label: 'benign' },
  { payload: "admin' OR 1=1 --", label: 'sqli' },
  { payload: "' OR 'a'='a", label: 'sqli' },
  { payload: '1; DROP TABLE accounts', label: 'sqli' },
  { payload: 'UNION SELECT email FROM users', label: 'sqli' },
  { payload: 'UN/**/ION SEL/**/ECT email FROM users', label: 'sqli' },
  { payload: '%55%4e%49%4f%4e%20%53%45%4c%45%43%54', label: 'sqli' },
  { payload: '<script>alert(1)</script>', label: 'xss' },
  { payload: '<img src=x onerror=alert(1)>', label: 'xss' },
  { payload: '<svg onload=alert(1)>', label: 'xss' },
  { payload: 'javascript:alert(1)', label: 'xss' },
  { payload: '%253Cscript%253Ealert(1)%253C%252Fscript%253E', label: 'xss' }
];

describe('Detection corpus', () => {
  it('reports detection rates over common benign and adversarial patterns', () => {
    const report = evaluatePayloads(corpus, { level: 'balanced' });

    expect(report.summary).toEqual(expect.objectContaining({
      total: corpus.length,
      labeled: corpus.length,
      falsePositives: 0,
      falseNegatives: 0
    }));
    expect(report.summary.truePositives).toBeGreaterThanOrEqual(10);
    expect(report.summary.trueNegatives).toBe(4);
    expect(report.summary.falsePositiveRate).toBe(0);
    expect(report.summary.falseNegativeRate).toBe(0);
  });
});
