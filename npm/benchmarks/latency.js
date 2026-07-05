#!/usr/bin/env node

const { performance } = require('perf_hooks');
const { Detector, expressMiddleware } = require('../src/detector');

const detector = new Detector();
const middleware = expressMiddleware({
  mode: 'log',
  scanHeaders: false,
  maxSuspiciousRequests: 999999
});

const samples = [
  'hello world',
  'normal search text',
  "O'Brien account",
  ['UN', 'ION SEL', 'ECT email FROM users'].join(''),
  ['<scr', 'ipt>alert(1)</scr', 'ipt>'].join('')
];

function percentile(values, pct) {
  const sorted = values.slice().sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.floor(sorted.length * pct));
  return sorted[index];
}

async function bench(name, iterations, run) {
  const timings = [];
  const started = performance.now();

  for (let i = 0; i < iterations; i++) {
    const before = performance.now();
    await run(i);
    timings.push(performance.now() - before);
  }

  const totalMs = performance.now() - started;
  return {
    name,
    iterations,
    totalMs: Number(totalMs.toFixed(2)),
    throughputPerSecond: Number((iterations / (totalMs / 1000)).toFixed(2)),
    p50Ms: Number(percentile(timings, 0.5).toFixed(4)),
    p95Ms: Number(percentile(timings, 0.95).toFixed(4))
  };
}

function requestFor(sample) {
  return {
    method: 'GET',
    url: `/search?q=${encodeURIComponent(sample)}`,
    query: { q: sample },
    headers: {},
    ip: '127.0.0.1'
  };
}

async function main() {
  const iterations = Number(process.env.SQLGUARDJS_BENCH_ITERATIONS || 5000);
  const results = [];

  results.push(await bench('detector.detect()', iterations, i => {
    detector.detect(samples[i % samples.length]);
  }));

  results.push(await bench('expressMiddleware()', iterations, i => new Promise((resolve, reject) => {
    const req = requestFor(samples[i % samples.length]);
    const res = {
      status() {
        return this;
      },
      json() {
        resolve();
      }
    };
    middleware(req, res, error => error ? reject(error) : resolve());
  })));

  console.table(results);
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
