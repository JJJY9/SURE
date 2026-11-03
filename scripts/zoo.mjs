#!/usr/bin/env node
// The SURE project zoo.
//
// A curated corpus of real projects — pinned by commit — that SURE is run
// against on demand, with a set of invariants and a committed baseline. The
// unit suites prove SURE's logic against fixtures this repository wrote; the
// zoo is the measurement against projects this repository did not write.
//
// Usage (from the repository root, after building):
//
//   node scripts/zoo.mjs                 # run every entry, compare with the baseline
//   node scripts/zoo.mjs --only chailv  # one entry
//   node scripts/zoo.mjs --offline       # reuse cached clones; skip entries with none
//   node scripts/zoo.mjs --update-baseline   # write what this run observed
//
// What it asserts, per entry — and none of it is about the checked project's
// own quality:
//
//   * SURE finished a check: exit 0 (green) or 1 (checked, not green). A crash,
//     a refused command line or an unfinished run is a zoo failure, not a
//     project result.
//   * The machine form parses and carries `details.report` with an aggregate.
//   * No check result is `error`: a checker that crashed is SURE's defect.
//   * Every skipped check carries a reason: "not run" must say why.
//   * Otherwise the run matches the committed baseline: the aggregate, the
//     findings and the not-checked list are identical to what the baseline
//     recorded. A difference is a behavior change SURE's own diff should
//     explain — either update the baseline in the same change and say why, or
//     fix what moved. The baseline is kept per runner platform (win32, linux,
//     darwin): a Linux CI run compares against the Linux baseline, and a
//     platform without one reports every entry as new rather than borrowing
//     another platform's answer.
//
// Honesty rules (the same ones the product holds itself to):
//
//   * An entry this machine cannot run (missing local path, no clone in
//     --offline mode) is recorded as skipped with the reason — never as a
//     pass, never as a silent absence.
//   * A local entry whose working tree has uncommitted changes is measured and
//     set aside as DIRTY: its findings are reported, but it is not compared
//     with the baseline. `--update-baseline` records it, because running the
//     update is a person's deliberate act and the reading is what they chose to
//     record — the compare path, which runs unattended, is where a moving tree
//     must not be allowed to report itself as the expected state.
//   * The settings file the zoo writes disables the analysis provider, so two
//     runs of the same commit compare without model variance.
//   * Clones are cached under target/tmp and reused only at the same commit.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const DEFAULT_MANIFEST = path.join(ROOT, 'evaluation', 'zoo', 'projects.json');
const DEFAULT_BASELINE = path.join(ROOT, 'evaluation', 'zoo', 'baseline.json');
const CACHE_ROOT = path.join(ROOT, 'target', 'tmp', 'zoo', 'cache');
const RUNS_ROOT = path.join(ROOT, 'target', 'tmp', 'zoo', 'runs');

function fail(message) {
  console.error(`zoo: ${message}`);
  process.exit(2);
}

function parseArgs(argv) {
  const opts = {
    manifest: DEFAULT_MANIFEST,
    baseline: DEFAULT_BASELINE,
    sure: null,
    only: null,
    offline: false,
    updateBaseline: false,
    timeoutMs: 20 * 60 * 1000,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) fail(`missing value for ${arg}`);
      return argv[i];
    };
    switch (arg) {
      case '--manifest':
        opts.manifest = path.resolve(next());
        break;
      case '--baseline':
        opts.baseline = path.resolve(next());
        break;
      case '--sure':
        opts.sure = next();
        break;
      case '--only':
        opts.only = new Set(next().split(',').map((s) => s.trim()).filter(Boolean));
        break;
      case '--offline':
        opts.offline = true;
        break;
      case '--update-baseline':
        opts.updateBaseline = true;
        break;
      case '--timeout-minutes':
        opts.timeoutMs = Number(next()) * 60 * 1000;
        break;
      case '--help':
      case '-h':
        console.log(
          'usage: node scripts/zoo.mjs [--manifest FILE] [--baseline FILE] [--sure BIN] ' +
            '[--only id,id] [--offline] [--update-baseline] [--timeout-minutes N]'
        );
        process.exit(0);
        break;
      default:
        fail(`unknown argument: ${arg}`);
    }
  }
  return opts;
}

function onPath(name) {
  if (name.includes('/') || name.includes('\\')) return null;
  const which = spawnSync(process.platform === 'win32' ? 'where' : 'which', [name], {
    encoding: 'utf8',
    windowsHide: true,
  });
  const hit = (which.stdout ?? '').split(/\r?\n/)[0]?.trim();
  return which.status === 0 && hit && fs.existsSync(hit) ? hit : null;
}

function resolveSure(explicit) {
  // `--sure` 是调用者点名要量的二进制:找到了就用它,找不到就停下——
  // 绝不悄悄换成另一个构建。2026-11-02:传入 `cmd.exe` 时 `existsSync`
  // 因为没有扩展名而失配,运行静默量了 release 构建,报告里的二进制不是
  // 所指的那个。
  if (explicit) {
    if (fs.existsSync(explicit)) return path.resolve(explicit);
    const hit = onPath(explicit);
    if (hit) return hit;
    fail(`找不到 --sure 指定的二进制: ${explicit}`);
  }
  // 本仓库的量具优先量本仓库的构建:这台机器上的 SURE_BIN 可能指向一个旧的
  // 安装版(2026-11-02 实测:SURE_BIN 指向 10-22 的构建,chailv 的 lint/类型检查
  // 因此被计划成裸模块)。SURE_BIN 与 PATH 只在仓库里没有构建时兜底。
  const candidates = [
    path.join(ROOT, 'target', 'release', 'sure.exe'),
    path.join(ROOT, 'target', 'release', 'sure'),
    path.join(ROOT, 'target', 'debug', 'sure.exe'),
    path.join(ROOT, 'target', 'debug', 'sure'),
    process.env.SURE_BIN,
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return path.resolve(candidate);
  }
  const hit = onPath('sure');
  if (hit) return hit;
  return null;
}

function runCapture(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 64 * 1024 * 1024,
    ...options,
  });
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    error: result.error ? String(result.error.message ?? result.error) : null,
  };
}

function ensureGitProject(entry, opts) {
  const dir = path.join(CACHE_ROOT, `${entry.id}-${entry.commit.slice(0, 12)}`);
  const marker = path.join(dir, '.zoo-ready');
  if (fs.existsSync(marker)) return { dir };
  if (opts.offline) {
    return { skipped: '离线模式下没有这个提交的本地克隆(target/tmp/zoo/cache)' };
  }
  fs.mkdirSync(dir, { recursive: true });
  const steps = [
    ['init', '-q'],
    ['remote', 'add', 'origin', entry.repo],
    ['fetch', '--depth', '1', 'origin', entry.commit],
    ['-c', 'advice.detachedHead=false', 'checkout', '-q', '--detach', 'FETCH_HEAD'],
  ];
  for (const [index, args] of steps.entries()) {
    // 第一次 remote add 在重复执行时会失败;目录是新的,只有半途失败才会撞上,
    // 此时把目录删掉重来比在错误上打补丁干净。
    const result = runCapture('git', args, { cwd: dir });
    if (result.status !== 0) {
      const detail = (result.stderr || result.stdout || result.error || '').trim().slice(0, 400);
      return { error: `git ${args.join(' ')} 失败(第 ${index + 1} 步): ${detail}` };
    }
  }
  fs.writeFileSync(marker, `${entry.repo}\n${entry.commit}\n`, 'utf8');
  return { dir };
}

// 项目自带的解释器目录(.venv / venv),按平台取 Scripts 或 bin。
// 与被核查的 MiQi 面板同一条判断:项目把解释器放在这里时,SURE 计划的
// `python -m …` 必须解析到项目自己的那份,否则跑的是机器上的全局解释器。
function projectVenv(dir) {
  const roots = [path.join(dir, '.venv'), path.join(dir, 'venv')];
  const bins = process.platform === 'win32' ? ['Scripts'] : ['bin'];
  for (const root of roots) {
    for (const bin of bins) {
      const candidate = path.join(root, bin);
      if (fs.existsSync(candidate)) return candidate;
    }
  }
  return null;
}

function childEnv(venvDir) {
  const env = { ...process.env };
  if (venvDir) {
    const key = process.platform === 'win32' ? 'Path' : 'PATH';
    const current = env[key] ?? env.PATH ?? '';
    env[key] = current ? `${venvDir}${path.delimiter}${current}` : venvDir;
    env.PATH = env[key];
  }
  return env;
}

function localProject(entry) {
  if (!fs.existsSync(entry.path) || !fs.statSync(entry.path).isDirectory()) {
    return { skipped: `本机没有该目录: ${entry.path}` };
  }
  const head = runCapture('git', ['-C', entry.path, 'rev-parse', '--short', 'HEAD']);
  const dirty = runCapture('git', ['-C', entry.path, 'status', '--porcelain']);
  return {
    dir: entry.path,
    gitHead: head.status === 0 ? head.stdout.trim() : null,
    gitDirty: dirty.status === 0 ? dirty.stdout.trim().length > 0 : null,
  };
}

function writeSettings(file, profile) {
  const lines = [
    'execution:',
    `  mode: ${profile.execution_mode}`,
    `  allow_dependency_install: ${profile.allow_dependency_install}`,
    `  allow_network: ${profile.allow_network}`,
    'analysis:',
    '  provider: disabled',
    '',
  ];
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${lines.join('\n')}\n`, 'utf8');
}

function parseEnvelope(stdout) {
  const lines = stdout.split(/\r?\n/).filter((line) => line.trim().length > 0);
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    try {
      const value = JSON.parse(lines[i]);
      if (value && typeof value === 'object') return value;
    } catch {
      // keep looking backwards: warnings may follow the frame on stdout?
      // (they should not, but a frame preceded by noise is still a frame)
    }
  }
  return null;
}

function summarize(envelope) {
  const report = envelope?.details?.report;
  if (!report || typeof report !== 'object') return null;
  const aggregate = report.aggregate ?? {};
  return {
    severity: String(aggregate.severity ?? 'unknown'),
    isGreen: Boolean(aggregate.is_green),
    totals: report.totals ?? {},
    findings: (report.findings ?? [])
      .map((f) => `${f.severity} | ${f.status} | ${f.title}`)
      .sort(),
    notChecked: (report.not_checked ?? []).map((row) => row.title ?? '(untitled)').sort(),
    checkResults: (envelope.details.check_results ?? [])
      .map((row) => `${row.status} | ${row.title}`)
      .sort(),
  };
}

function invariants(exitCode, envelope, summary) {
  const problems = [];
  if (exitCode !== 0 && exitCode !== 1) {
    problems.push(`退出码 ${exitCode === null ? '(被终止/超时)' : exitCode}:核查没有完成(只接受 0=绿 / 1=已查但非绿)`);
  }
  if (!envelope) {
    problems.push('stdout 里没有可解析的 JSON 帧');
    return problems;
  }
  if (envelope.command !== 'check') {
    problems.push(`帧的 command 是 ${JSON.stringify(envelope.command)},不是 check`);
  }
  if (!summary) {
    problems.push('帧里没有 details.report');
    return problems;
  }
  for (const row of envelope.details?.check_results ?? []) {
    if (row.status === 'error') {
      problems.push(`检查器崩溃(SURE 自身的缺陷,不是项目的问题): ${row.title}`);
    }
    if (row.status === 'skipped' && !String(row.reason ?? '').trim()) {
      problems.push(`未运行的检查没有给出原因: ${row.title}`);
    }
  }
  return problems;
}

function loadBaseline(file) {
  if (!fs.existsSync(file)) return { schema_version: 2, platforms: {} };
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    fail(`基线文件无法解析(${file}): ${error.message}`);
  }
  if (
    parsed.schema_version !== 2 ||
    typeof parsed.platforms !== 'object' ||
    parsed.platforms === null
  ) {
    fail(`基线文件不是 schema_version 2(按平台的 platforms): ${file}——用 --update-baseline 重新生成`);
  }
  return parsed;
}

function comparable(summary) {
  return {
    severity: summary.severity,
    findings: summary.findings,
    notChecked: summary.notChecked,
    checkResults: summary.checkResults,
  };
}

function diffSummary(previous, current) {
  const diffs = [];
  if (previous.severity !== current.severity) {
    diffs.push(`severity: ${previous.severity} → ${current.severity}`);
  }
  for (const field of ['findings', 'notChecked', 'checkResults']) {
    const before = new Set(previous[field] ?? []);
    const after = new Set(current[field] ?? []);
    for (const item of after) if (!before.has(item)) diffs.push(`+ ${field}: ${item}`);
    for (const item of before) if (!after.has(item)) diffs.push(`- ${field}: ${item}`);
  }
  return diffs;
}

function fmtDuration(ms) {
  return `${(ms / 1000).toFixed(1)}s`;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!fs.existsSync(opts.manifest)) fail(`清单不存在: ${opts.manifest}`);
  const manifest = JSON.parse(fs.readFileSync(opts.manifest, 'utf8'));
  const sure = resolveSure(opts.sure);
  if (!sure) {
    fail('找不到 SURE 二进制:用 --sure 或 SURE_BIN 指定,或先 cargo build --release');
  }
  const versionResult = runCapture(sure, ['--version']);
  const sureVersion = versionResult.status === 0 ? versionResult.stdout.trim() : '(unknown)';

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const runDir = path.join(RUNS_ROOT, stamp);
  fs.mkdirSync(runDir, { recursive: true });

  const baseline = loadBaseline(opts.baseline);
  const platform = process.platform;
  const entries = manifest.projects.filter((entry) => !opts.only || opts.only.has(entry.id));
  if (opts.only && entries.length === 0) fail(`--only 没有匹配任何条目: ${[...opts.only].join(',')}`);

  const results = [];
  for (const entry of entries) {
    const result = {
      id: entry.id,
      kind: entry.kind,
      profile: entry.profile,
      status: 'ERROR',
      note: '',
      durationMs: 0,
    };
    const started = Date.now();
    try {
      const location = entry.kind === 'git' ? ensureGitProject(entry, opts) : localProject(entry);
      if (location.skipped) {
        result.status = 'SKIPPED';
        result.note = location.skipped;
        continue;
      }
      if (location.error) {
        result.status = 'ERROR';
        result.note = location.error;
        continue;
      }
      result.projectPath = location.dir;
      const venvDir = projectVenv(location.dir);
      if (venvDir) result.venvOnPath = venvDir;
      if (entry.kind === 'local') {
        result.gitHead = location.gitHead ?? null;
        result.gitDirty = location.gitDirty ?? null;
      }
      const profile = manifest.profiles?.[entry.profile];
      if (!profile) {
        result.status = 'ERROR';
        result.note = `清单里的 profile 未定义: ${entry.profile}`;
        continue;
      }
      const settingsFile = path.join(runDir, `settings-${entry.id}.yaml`);
      writeSettings(settingsFile, profile);
      const storeDir = path.join(runDir, `store-${entry.id}`);
      fs.mkdirSync(storeDir, { recursive: true });
      const check = runCapture(
        sure,
        [
          '--format',
          'json',
          '--settings-file',
          settingsFile,
          '--store-dir',
          storeDir,
          'check',
          location.dir,
        ],
        { cwd: runDir, timeout: opts.timeoutMs, env: childEnv(venvDir) }
      );
      fs.writeFileSync(path.join(runDir, `${entry.id}.stdout.log`), check.stdout, 'utf8');
      fs.writeFileSync(path.join(runDir, `${entry.id}.stderr.log`), check.stderr, 'utf8');
      const envelope = parseEnvelope(check.stdout);
      const summary = summarize(envelope);
      result.exitCode = check.status;
      if (summary) {
        result.severity = summary.severity;
        result.isGreen = summary.isGreen;
        result.totals = summary.totals;
        result.findings = summary.findings;
        result.notChecked = summary.notChecked;
        result.checkResults = summary.checkResults;
      }
      const problems = invariants(check.status, envelope, summary);
      if (problems.length > 0) {
        result.status = 'FAILED';
        result.note = problems.join('; ');
        continue;
      }
      // 本地条目衡量的是这台机器上的实时项目。工作区有未提交改动时,它是一个
      // 移动靶:测到的发现项属于当前编辑中的状态,与基线比较只会把"别人正在
      // 改代码"报成回归,而 `--update-baseline` 会把一个瞬时状态固化成预期。
      // 照常测量、照常列出发现项,但标成 DIRTY:不参与比较,也不写进基线。
      if (entry.kind === 'local' && result.gitDirty) {
        result.status = 'DIRTY';
        result.note = '工作区有未提交改动——本次只测量,不与基线比较';
        continue;
      }
      const previous = baseline.platforms?.[platform]?.entries?.[entry.id];
      if (!previous) {
        result.status = 'NEW';
        result.note = `基线里没有 ${platform} 平台下该条目的记录——用 --update-baseline 记录本次结果`;
        continue;
      }
      if (previous.sure_version !== sureVersion) {
        // 版本变化本身不是漂移的证据:比较的是行为,报告里注明版本即可。
        result.versionChanged = `${previous.sure_version} → ${sureVersion}`;
      }
      const diffs = diffSummary(previous, comparable(summary));
      if (diffs.length === 0) {
        result.status = 'MATCH';
      } else {
        result.status = 'CHANGED';
        result.note = diffs.slice(0, 8).join('\n    ');
      }
    } finally {
      result.durationMs = Date.now() - started;
      results.push(result);
    }
  }

  // --update-baseline:只有在这次运行里真实拿到结论的条目才更新,且只更新
  // 当前运行平台的那一档——另一个平台的基线原样保留。
  if (opts.updateBaseline) {
    const next = { schema_version: 2, platforms: { ...baseline.platforms } };
    const current = {
      sure_version: sureVersion,
      entries: { ...(baseline.platforms?.[platform]?.entries ?? {}) },
    };
    for (const result of results) {
      // `--update-baseline` 是人的明确动作:比较模式把脏的本地条目搁置,但
      // 人主动记录时照他要的记(带 DIRTY 的原因写在报告里)。
      if (['MATCH', 'NEW', 'CHANGED', 'DIRTY'].includes(result.status)) {
        current.entries[result.id] = {
          sure_version: sureVersion,
          severity: result.severity,
          findings: result.findings,
          notChecked: result.notChecked,
          checkResults: result.checkResults,
        };
      }
    }
    next.platforms[platform] = current;
    fs.mkdirSync(path.dirname(opts.baseline), { recursive: true });
    fs.writeFileSync(opts.baseline, `${JSON.stringify(next, null, 2)}\n`, 'utf8');
  }

  const report = {
    ran_at: new Date().toISOString(),
    platform,
    sure,
    sure_version: sureVersion,
    manifest: opts.manifest,
    baseline: opts.baseline,
    offline: opts.offline,
    updated_baseline: opts.updateBaseline,
    results,
  };
  fs.writeFileSync(path.join(runDir, 'zoo-report.json'), `${JSON.stringify(report, null, 2)}\n`, 'utf8');

  console.log(`zoo: SURE ${sureVersion} (${sure})`);
  console.log(`zoo: 平台 ${platform}${opts.updateBaseline ? '(本次记录该平台基线)' : ''}`);
  console.log(`zoo: ${entries.length} 个条目,运行目录 ${runDir}`);
  console.log('');
  const header = ['条目', '结果', '结论', '已核查', '未运行', '发现项', '耗时'];
  const rows = results.map((r) => [
    r.id,
    r.status,
    r.severity ?? '-',
    String(r.totals?.checked ?? '-'),
    String((r.totals?.skipped ?? 0) + (r.totals?.could_not_run ?? 0)),
    String(r.findings?.length ?? '-'),
    fmtDuration(r.durationMs),
  ]);
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((row) => row[i].length)));
  const line = (cells) => cells.map((cell, i) => cell.padEnd(widths[i])).join('  ');
  console.log(line(header));
  console.log(widths.map((w) => '-'.repeat(w)).join('  '));
  for (const row of rows) console.log(line(row));
  console.log('');

  for (const result of results) {
    if (result.note) console.log(`  ${result.id} [${result.status}] ${result.note}`);
    if (result.versionChanged) console.log(`  ${result.id}: SURE 版本变化 ${result.versionChanged}`);
    if (result.venvOnPath) console.log(`  ${result.id}: 子进程 PATH 前置了项目 venv ${result.venvOnPath}`);
    if (result.kind === 'local') {
      console.log(
        `  ${result.id}: 本地 HEAD ${result.gitHead ?? '(非 git)'}${result.gitDirty ? ',工作区有未提交改动' : ''}`
      );
    }
  }
  console.log('');
  console.log(`zoo: 明细 ${path.join(runDir, 'zoo-report.json')}`);
  if (opts.updateBaseline) console.log(`zoo: 基线已更新 ${opts.baseline}`);

  // 记录模式下 CHANGED / NEW 已经写进基线,是这次运行的目的而不是失配,
  // 只剩真的失败(崩溃、不合规报告、超时)才该让任务标红。2026-11-02:记录
  // 模式曾把刚记录的条目也当失败,CI 的基线记录任务因此以 exit 1 结束。
  const failures = results.filter((r) =>
    ['ERROR', 'FAILED'].includes(r.status) ||
    (!opts.updateBaseline && ['CHANGED', 'NEW'].includes(r.status))
  );
  if (failures.length > 0) {
    const what = opts.updateBaseline ? '个条目失败' : '个条目需要处理';
    console.error(`zoo: ${failures.length} ${what}: ${failures.map((r) => r.id).join(', ')}`);
    process.exit(1);
  }
}

main();
