#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const util = require('util');
const { Detector } = require('../src/detector');

function printHelp() {
  console.log(`
SQLGuardJS (Heuristic Scanner)

Usage:
  sqlguardjs scan <payload>              - Scan a single payload
  sqlguardjs scan-file <filepath>        - Scan a file with one payload per line
  
Options:
  --format <json|csv>                    - Output format (default: json)
`);
}

function main() {
  const { values, positionals } = util.parseArgs({ 
    args: process.argv.slice(2), 
    options: { 
      format: { type: 'string', default: 'json' },
      help: { type: 'boolean', short: 'h', default: false }
    }, 
    allowPositionals: true 
  });
  
  if (values.help || positionals.length === 0) {
    printHelp();
    process.exit(0);
  }
  
  const command = positionals[0];
  const format = values.format;
  const args = positionals; // For compatibility with rest of the code
  
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
    
    let content;
    try {
      content = fs.readFileSync(filepath, 'utf8');
    } catch (err) {
      console.error(`Error: Failed to read file at ${filepath} (${err.message})`);
      process.exit(1);
    }
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
