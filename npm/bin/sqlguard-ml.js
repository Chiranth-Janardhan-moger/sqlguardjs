#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { Detector } = require('../src/detector');

function printHelp() {
  console.log(`
SQLGuard ML (Heuristic Scanner)

Usage:
  sqlguard-ml scan <payload>             - Scan a single payload
  sqlguard-ml scan-file <filepath>       - Scan a file with one payload per line
  
Options:
  --format <json|csv>                    - Output format (default: json)
`);
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }
  
  const command = args[0];
  let format = 'json';
  
  const formatIdx = args.indexOf('--format');
  if (formatIdx !== -1 && formatIdx + 1 < args.length) {
    format = args[formatIdx + 1];
    // remove format args to simplify positional arg parsing
    args.splice(formatIdx, 2);
  }
  
  const detector = new Detector();
  
  if (command === 'scan') {
    if (args.length < 2) {
      console.error('Error: Missing payload string');
      process.exit(1);
    }
    const payload = args.slice(1).join(' ');
    const result = detector.detect(payload);
    
    if (format === 'csv') {
      console.log('payload,label,confidence');
      console.log(`"${payload.replace(/"/g, '""')}","${result.label}",${result.confidence}`);
    } else {
      console.log(JSON.stringify({ payload, result }, null, 2));
    }
    
  } else if (command === 'scan-file') {
    if (args.length < 2) {
      console.error('Error: Missing filepath');
      process.exit(1);
    }
    const filepath = path.resolve(args[1]);
    if (!fs.existsSync(filepath)) {
      console.error(`Error: File not found at ${filepath}`);
      process.exit(1);
    }
    
    const content = fs.readFileSync(filepath, 'utf8');
    const payloads = content.split(/\r?\n/).filter(line => line.trim().length > 0);
    
    const results = payloads.map(p => ({ payload: p, result: detector.detect(p) }));
    
    if (format === 'csv') {
      console.log('payload,label,confidence');
      results.forEach(r => {
        console.log(`"${r.payload.replace(/"/g, '""')}","${r.result.label}",${r.result.confidence}`);
      });
    } else {
      console.log(JSON.stringify(results, null, 2));
    }
    
  } else {
    console.error(`Unknown command: ${command}`);
    printHelp();
    process.exit(1);
  }
}

main();
