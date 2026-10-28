'use strict';

// Break-glass password reset. Run this inside the backend container.
// The password is read from a hidden prompt or from stdin, never from argv.

const args = process.argv.slice(2);

const HELP = `Reset the Prowler Reviewer password from inside the backend container.

Interactive (password is not echoed):
  node reset-password.js

From stdin, when there is no terminal:
  node reset-password.js --password-stdin

Create the account when none exists yet:
  node reset-password.js --username <name>

This replaces the stored hash and signs out every session.
Do not pass the password as an argument.
`;

function optionValue(name) {
  const prefixed = args.find(arg => arg.startsWith(name + '='));
  if (prefixed) return prefixed.slice(name.length + 1);
  const index = args.indexOf(name);
  if (index === -1) return '';
  const value = args[index + 1];
  if (!value || value.startsWith('--')) return '';
  return value;
}

function refuseArgvPassword() {
  const bad = args.some(arg => arg === '--password' || arg.startsWith('--password='));
  if (!bad) return false;
  console.error('Refusing to read a password from the command line. Use the prompt or --password-stdin.');
  return true;
}

if (args.includes('-h') || args.includes('--help')) {
  process.stdout.write(HELP);
  process.exit(0);
}

if (refuseArgvPassword()) process.exit(1);

if (args.some(arg => arg.startsWith('--password-stdin='))) {
  console.error('--password-stdin does not take a value. Write the password to stdin instead.');
  process.exit(1);
}

const known = new Set(['--password-stdin', '--username', '--help', '-h']);
for (const arg of args) {
  if (arg.startsWith('--') && !known.has(arg.split('=')[0])) {
    console.error(`Unknown option: ${arg.split('=')[0]}`);
    process.stderr.write(HELP);
    process.exit(1);
  }
}

const readline = require('readline');
const { openAuthStore } = require('./auth');

function askVisible(promptText) {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(promptText, answer => {
      rl.close();
      resolve(answer);
    });
  });
}

function askHidden(promptText) {
  return new Promise(resolve => {
    const stdin = process.stdin;
    const stdout = process.stdout;
    stdout.write(promptText);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let value = '';
    const onData = ch => {
      if (ch === '\u0003') {
        stdin.setRawMode(false);
        stdout.write('\n');
        process.exit(130);
      }
      if (ch === '\r' || ch === '\n') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        stdout.write('\n');
        resolve(value);
        return;
      }
      if (ch === '\u007f' || ch === '\u0008') {
        value = value.slice(0, -1);
        return;
      }
      if (/[\u0000-\u001F\u007F]/.test(ch)) return;
      value += ch;
    };
    stdin.on('data', onData);
  });
}

function readStdinPassword() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    process.stdin.on('data', buf => {
      size += buf.length;
      if (size > 4096) {
        reject(new Error('Password input is too long.'));
        process.stdin.destroy();
        return;
      }
      chunks.push(buf);
    });
    process.stdin.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
      if (text.includes('\n') || text.includes('\r')) {
        reject(new Error('Password cannot include line breaks.'));
        return;
      }
      resolve(text);
    });
    process.stdin.on('error', reject);
  });
}

async function main() {
  const dataDir = process.env.DATA_DIR || '/data';
  const store = openAuthStore(dataDir);
  const stdinMode = args.includes('--password-stdin');
  let username = optionValue('--username');

  if (args.includes('--username') && !username) {
    console.error('--username needs a value.');
    process.exit(1);
  }

  let password;
  if (stdinMode) {
    try {
      password = await readStdinPassword();
    } catch (err) {
      console.error(err.message || 'Could not read the password.');
      process.exit(1);
    }
  } else if (process.stdin.isTTY) {
    if (!store.hasAccount()) {
      username = username || (await askVisible('Username: ')).trim();
    } else if (username) {
      console.error('An account already exists. The username was left unchanged.');
      username = '';
    }
    password = await askHidden('New password: ');
    const again = await askHidden('Confirm password: ');
    if (password !== again) {
      console.error('Passwords do not match.');
      process.exit(1);
    }
  } else {
    console.error('No terminal available. Use --password-stdin so the password is not passed as an argument.');
    process.exit(1);
  }

  const result = store.resetPassword(password, { username });
  if (!result.ok) {
    console.error(result.error);
    process.exit(result.code === 'no-account' || result.code === 'corrupt' ? 2 : 1);
  }
  console.log(result.created
    ? `Account created for ${result.username}.`
    : `Password updated for ${result.username}.`);
  console.log('All sessions have been signed out.');
}

main().catch(err => {
  console.error('Password reset failed.');
  if (process.env.DEBUG) console.error(err && err.message ? err.message : '');
  process.exit(1);
});
