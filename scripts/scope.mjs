#!/usr/bin/env node
/**
 * Rules-of-engagement CLI.
 *
 * Writes and inspects `.security-audit/scope.json`, the document the
 * authorization gate consults before any packet leaves the machine.
 *
 * Usage:
 *   node scope.mjs init --name "Acme Q3" --client Acme --type authorized-pentest
 *   node scope.mjs add-target --domains acme.com --ip-ranges 203.0.113.0/24
 *   node scope.mjs exclude --domains payments.acme.com
 *   node scope.mjs allow --rules activeTesting,passiveRecon
 *   node scope.mjs authorize --by "CISO" --reference SOW-2026-114 --until 2026-12-31
 *   node scope.mjs check "nmap -sV www.acme.com"
 *   node scope.mjs show
 */

import path from 'node:path';
import {
  loadScope, saveScope, defaultScope, evaluateCommand, scopePath,
} from './lib/scope.mjs';
import { parseArgs, emit, fail, nowIso } from './lib/util.mjs';

const args = parseArgs();
const command = args._[0];
const cwd = args.cwd ? path.resolve(String(args.cwd)) : process.cwd();

const list = (value) => (value ? String(value).split(',').map((s) => s.trim()).filter(Boolean) : []);
const merge = (existing, incoming) => [...new Set([...(existing ?? []), ...incoming])];

function requireScope() {
  const scope = loadScope(cwd);
  if (!scope) fail(`no scope at ${scopePath(cwd)}. Run \`scope.mjs init\` first.`);
  return scope;
}

switch (command) {
  case 'init': {
    if (loadScope(cwd) && !args.force) {
      fail(`a scope already exists at ${scopePath(cwd)}. Pass --force to overwrite it.`);
    }
    const scope = defaultScope();
    scope.engagement.name = String(args.name ?? '');
    scope.engagement.client = String(args.client ?? '');
    scope.engagement.auditor = String(args.auditor ?? '');
    scope.engagement.type = String(args.type ?? 'self-owned');
    if (args.until) scope.engagement.endsAt = new Date(String(args.until)).toISOString();
    scope.engagement.startsAt = nowIso();

    // Owning the target is the only case where testing needs no counterparty.
    if (scope.engagement.type === 'self-owned') {
      scope.authorization.granted = true;
      scope.authorization.grantedBy = 'self (asset owner)';
      scope.authorization.attestedAt = nowIso();
      scope.authorization.attestation = 'The operator asserts ownership of, or written permission to test, every declared target.';
      scope.rules.passiveRecon = true;
    }

    saveScope(scope, cwd);
    emit({ created: scopePath(cwd), engagement: scope.engagement, authorization: scope.authorization, rules: scope.rules });
    break;
  }

  case 'add-target': {
    const scope = requireScope();
    const t = scope.targets;
    t.repos = merge(t.repos, list(args.repos));
    t.hosts = merge(t.hosts, list(args.hosts));
    t.domains = merge(t.domains, list(args.domains));
    t.urls = merge(t.urls, list(args.urls));
    t.ipRanges = merge(t.ipRanges, list(args['ip-ranges']));
    t.cloudAccounts = merge(t.cloudAccounts, list(args['cloud-accounts']));
    t.mobileApps = merge(t.mobileApps, list(args['mobile-apps']));
    t.wireless.ssids = merge(t.wireless.ssids, list(args.ssids));
    t.wireless.bssids = merge(t.wireless.bssids, list(args.bssids).map((b) => b.toUpperCase()));
    saveScope(scope, cwd);
    emit(scope.targets);
    break;
  }

  case 'exclude': {
    const scope = requireScope();
    const o = scope.outOfScope;
    o.hosts = merge(o.hosts, list(args.hosts));
    o.domains = merge(o.domains, list(args.domains));
    o.ipRanges = merge(o.ipRanges, list(args['ip-ranges']));
    if (args.note) o.notes = merge(o.notes, [String(args.note)]);
    saveScope(scope, cwd);
    emit(scope.outOfScope);
    break;
  }

  case 'allow':
  case 'deny': {
    const scope = requireScope();
    const enable = command === 'allow';
    const rules = list(args.rules ?? args._[1]);
    if (!rules.length) fail(`usage: scope.mjs ${command} --rules activeTesting,exploitation`);
    for (const rule of rules) {
      if (!(rule in scope.rules)) fail(`unknown rule "${rule}". Valid: ${Object.keys(scope.rules).filter((k) => typeof scope.rules[k] === 'boolean').join(', ')}`);
      scope.rules[rule] = enable;
    }
    saveScope(scope, cwd);
    emit(scope.rules);
    break;
  }

  case 'authorize': {
    const scope = requireScope();
    if (!args.by || !args.reference) {
      fail('usage: scope.mjs authorize --by "<name or role>" --reference "<contract, ticket or SOW>" [--until YYYY-MM-DD]\n'
        + 'Both are required: an authorization nobody can trace back to a document is not an authorization.');
    }
    scope.authorization = {
      granted: true,
      grantedBy: String(args.by),
      reference: String(args.reference),
      attestedAt: nowIso(),
      attestation: String(args.attestation ?? 'Written permission to test the declared targets has been obtained and is retained by the auditor.'),
    };
    if (args.until) scope.engagement.endsAt = new Date(String(args.until)).toISOString();
    saveScope(scope, cwd);
    emit({ authorization: scope.authorization, endsAt: scope.engagement.endsAt });
    break;
  }

  case 'revoke': {
    const scope = requireScope();
    scope.authorization.granted = false;
    scope.authorization.attestation = `Revoked ${nowIso()}. ${scope.authorization.attestation ?? ''}`.trim();
    saveScope(scope, cwd);
    emit({ authorization: scope.authorization });
    break;
  }

  case 'check': {
    const cmd = args._.slice(1).join(' ') || String(args.command ?? '');
    if (!cmd) fail('usage: scope.mjs check "<shell command>"');
    const verdict = evaluateCommand(cmd, cwd);
    emit(verdict);
    if (verdict.decision !== 'allow') process.exit(2);
    break;
  }

  case 'show': {
    const scope = loadScope(cwd);
    if (!scope) {
      emit({ exists: false, path: scopePath(cwd), note: 'No rules of engagement recorded. Active testing is blocked until one exists.' });
      break;
    }
    const { _path, ...body } = scope;
    emit(body);
    break;
  }

  default:
    process.stderr.write([
      'usage: scope.mjs <command>',
      '',
      '  init --name --client --type <self-owned|authorized-pentest|bug-bounty|internal>',
      '  add-target --domains --hosts --urls --ip-ranges --ssids --bssids --repos',
      '  exclude --domains --hosts --ip-ranges --note',
      '  allow  --rules passiveRecon,activeTesting,exploitation,denialOfService',
      '  deny   --rules ...',
      '  authorize --by "<name>" --reference "<SOW or ticket>" [--until YYYY-MM-DD]',
      '  revoke',
      '  check "<command>"        dry-run the authorization gate',
      '  show',
      '',
    ].join('\n'));
    process.exit(1);
}
