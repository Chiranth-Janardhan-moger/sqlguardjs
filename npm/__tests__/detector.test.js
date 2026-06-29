const { Detector } = require('../src/detector');

describe('Detector', () => {
  let detector;

  beforeEach(() => {
    detector = new Detector();
  });

  test('should detect benign payloads', () => {
    const result = detector.detect('hello world');
    expect(result.label).toBe('benign');
    expect(result.confidence).toBe(0);
  });

  test('should detect basic SQLi', () => {
    const result = detector.detect("' OR '1'='1");
    expect(result.label).toBe('sqli');
    expect(result.confidence).toBeGreaterThan(0);
  });

  test('should detect basic XSS', () => {
    const result = detector.detect('<script>alert("XSS")</script>');
    expect(result.label).toBe('xss');
    expect(result.confidence).toBeGreaterThan(0);
  });
});
