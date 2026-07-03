#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const util = require('util');
const { Detector } = require('../src/detector');

const MAX_CLI_PAYLOAD_LENGTH = 50000;

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

function csvCell(value) {
  const text = String(value)
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n');
  const formulaSafeText = /^[\t ]*[=+\-@]/.test(text) ? `'${text}` : text;
  return `"${formulaSafeText.replace(/"/g, '""')}"`;
}

function payloadForOutput(payload) {
  const text = String(payload);
  if (text.length <= MAX_CLI_PAYLOAD_LENGTH) return text;
  return `${text.slice(0, MAX_CLI_PAYLOAD_LENGTH)}...[truncated ${text.length - MAX_CLI_PAYLOAD_LENGTH} chars]`;
}

async function scanFile(filepath, format, detector) {
  try {
    await fs.promises.access(filepath, fs.constants.R_OK);
  } catch (err) {
    console.error(`Error: Failed to read file at ${filepath} (${err.message})`);
    process.exit(1);
  }

  const stream = fs.createReadStream(filepath, { encoding: 'utf8' });
  const lines = readline.createInterface({ input: stream, crlfDelay: Infinity });

  if (format === 'csv') {
    console.log('payload,label,confidence');
  } else {
    process.stdout.write('[\n');
  }

  let isFirstJsonRow = true;
  try {
    for await (const line of lines) {
      if (line.trim().length === 0) continue;
      const result = detector.detect(line);
      const row = { payload: payloadForOutput(line), result };
      if (format === 'csv') {
        console.log(`${csvCell(row.payload)},${csvCell(result.label)},${result.confidence}`);
      } else {
        process.stdout.write(`${isFirstJsonRow ? '' : ',\n'}${JSON.stringify(row, null, 2)}`);
        isFirstJsonRow = false;
      }
    }
  } catch (err) {
    console.error(`Error: Failed to read file at ${filepath} (${err.message})`);
    process.exit(1);
  }

  if (format !== 'csv') {
    process.stdout.write(isFirstJsonRow ? ']\n' : '\n]\n');
  }
}

async function main() {
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
      console.log(`${csvCell(payloadForOutput(payload))},${csvCell(result.label)},${result.confidence}`);
    } else {
      console.log(JSON.stringify({ payload: payloadForOutput(payload), result }, null, 2));
    }
    
  } else if (command === 'scan-file') {
    if (args.length < 2) {
      console.error('Error: Missing filepath');
      process.exit(1);
    }
    const filepath = path.resolve(args[1]);
    
    await scanFile(filepath, format, detector);
    
  } else {
    console.error(`Unknown command: ${command}`);
    printHelp();
    process.exit(1);
  }
}

main().catch(err => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
