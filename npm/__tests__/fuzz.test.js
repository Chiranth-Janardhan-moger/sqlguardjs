const { Detector, expressMiddleware } = require('../src/detector');

function encodeNTimes(value, count) {
  return Array.from({ length: count }).reduce(encoded => encodeURIComponent(encoded), value);
}

describe('Generated adversarial and benign corpora', () => {
  let detector;

  beforeEach(() => {
    detector = new Detector();
  });

  it('blocks generated SQL boolean predicate variants across operators and wrappers', () => {
    const booleanOps = ['OR', 'AND', 'XOR', '||', '&&'];
    const comparisons = ['2>1', '3!=4', '4<>5', '5>=5', '1<=2', "'a'<'b'", 'CHAR(49)=CHAR(49)'];
    const prefixes = ["admin'", '1 ', "')", 'id=1 '];
    const suffixes = ['', '--', '#', '/*tail*/'];

    for (const booleanOp of booleanOps) {
      for (const comparison of comparisons) {
        for (const prefix of prefixes) {
          const suffix = suffixes[(booleanOp.length + comparison.length + prefix.length) % suffixes.length];
          const payload = `${prefix}${booleanOp} ${comparison}${suffix}`;
          const result = detector.detect(payload);

          expect(result.label).toBe('sqli');
          expect(result.confidence).toBeGreaterThanOrEqual(0.5);
          expect(result.matches.map(match => match.id)).toContain('sql-structural-boolean');
        }
      }
    }
  });

  it('blocks generated stacked metadata enumeration variants', () => {
    const wrappers = [
      ';SELECT COUNT(*) FROM',
      ';(SELECT COUNT(*) FROM',
      ';((SELECT table_name FROM',
      ';WITH q AS (SELECT * FROM'
    ];
    const catalogs = [
      'information_schema.columns',
      'all_tables',
      'user_tab_columns',
      'dba_objects',
      'mysql.innodb_table_stats',
      'mysql.user',
      'sys.columns',
      'sys.objects',
      'pg_catalog.pg_tables',
      'pg_class',
      'sqlite_master'
    ];

    for (const wrapper of wrappers) {
      for (const catalog of catalogs) {
        const payload = `1${wrapper} ${catalog})`;
        const result = detector.detect(payload);

        expect(result.label).toBe('sqli');
        expect(result.confidence).toBeGreaterThanOrEqual(0.5);
        expect(result.matches.map(match => match.id)).toEqual(expect.arrayContaining([
          'sql-structural-stacked-statement',
          'sql-structural-metadata-query'
        ]));
      }
    }
  });

  it('blocks generated JavaScript pseudo-protocol execution variants', () => {
    const payloads = [
      'javascript:alert(1)',
      'javascript:confirm(1)',
      'javascript:window["alert"](1)',
      'javascript:globalThis["al"+"ert"](1)',
      'javascript:[][`constructor`][`constructor`](`alert(1)`)()',
      'java\\u0073cript:[]["constructor"]["constructor"]("alert(1)")()',
      encodeNTimes('javascript:top["alert"](1)', 2)
    ];

    for (const payload of payloads) {
      const result = detector.detect(payload);

      expect(result.label).toBe('xss');
      expect(result.confidence).toBeGreaterThanOrEqual(0.5);
      expect(result.matches.map(match => match.id)).toContain('javascript-url-structural-sink');
    }
  });

  it('keeps benign traffic and security documentation samples under the block threshold', async () => {
    const middleware = expressMiddleware();
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    const next = jest.fn();
    const benignSamples = [
      'If x = 1 and y = 1 then x = y.',
      'The all_tables view is documented in Oracle guides.',
      'Our report mentions sys.columns as a SQL Server catalog view.',
      'Use SELECT in examples only with parameterized queries.',
      'javascript is a programming language, not a URL here.',
      'The constructor pattern appears in JavaScript tutorials.',
      'Please show tables in the documentation sidebar.',
      'The union of two sets can be described with AND and OR in prose.'
    ];

    for (const sample of benignSamples) {
      await middleware({ body: { text: sample }, ip: `198.51.100.${next.mock.calls.length + 1}` }, res, next);
    }

    expect(res.status).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(benignSamples.length);
  });
});
