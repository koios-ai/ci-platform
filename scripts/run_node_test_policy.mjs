import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";

const SAFE_PATH = /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*\.(?:cjs|js|mjs)$/;
const expectedKeys = ["adapter", "test_files", "unexpected_skip_policy", "version"];

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

function parseCount(output, name) {
  const matches = [...output.matchAll(new RegExp(`^# ${name} (\\d+)$`, "gm"))];
  if (matches.length !== 1) {
    fail(`node TAP output has no unique ${name} count`);
  }
  return Number(matches[0][1]);
}

function counts(output) {
  const value = {
    tests: parseCount(output, "tests"),
    passed: parseCount(output, "pass"),
    failed: parseCount(output, "fail"),
    skipped: parseCount(output, "skipped"),
    todo: parseCount(output, "todo"),
  };
  if (
    value.tests <= 0 ||
    value.passed !== value.tests ||
    value.failed !== 0 ||
    value.skipped !== 0 ||
    value.todo !== 0
  ) {
    fail(`node test file was not fully green: ${JSON.stringify(value)}`);
  }
  return value;
}

if (process.argv.length !== 6 || process.argv[2] !== "--policy" || process.argv[4] !== "--output") {
  fail("usage: run_node_test_policy.mjs --policy PATH --output DIR");
}
const policyPath = path.resolve(process.argv[3]);
const output = path.resolve(process.argv[5] ?? "");
if (!output) {
  fail("node evidence output path is missing");
}
const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
if (
  Object.keys(policy).sort().join("\0") !== expectedKeys.sort().join("\0") ||
  policy.version !== 1 ||
  policy.adapter !== "node-test" ||
  policy.unexpected_skip_policy !== "fail" ||
  !Array.isArray(policy.test_files) ||
  policy.test_files.length === 0 ||
  policy.test_files.length > 128 ||
  new Set(policy.test_files).size !== policy.test_files.length ||
  policy.test_files.some((item) => typeof item !== "string" || !SAFE_PATH.test(item))
) {
  fail("protected Node test policy is invalid");
}

fs.mkdirSync(output, { recursive: true });
const perFile = {};
const tap = [];
for (const relative of policy.test_files) {
  const candidate = path.resolve("/workspace/target", relative);
  if (!candidate.startsWith("/workspace/target/") || !fs.statSync(candidate).isFile()) {
    fail(`declared Node test file is unavailable: ${relative}`);
  }
  const result = spawnSync(
    process.execPath,
    ["--test", "--test-reporter=tap", candidate],
    {
      cwd: "/workspace/target",
      encoding: "utf8",
      env: {
        CI: "true",
        HOME: "/tmp",
        NODE_PATH: "/workspace/target/node_modules",
        PATH: process.env.PATH,
      },
      maxBuffer: 10_000_000,
      timeout: 1_800_000,
    },
  );
  tap.push(`### ${relative}\n${result.stdout}${result.stderr}`);
  if (result.error || result.status !== 0) {
    fail(`declared Node test file failed: ${relative}`);
  }
  perFile[relative] = counts(result.stdout);
}
const totals = { tests: 0, passed: 0, failed: 0, skipped: 0, todo: 0 };
for (const value of Object.values(perFile)) {
  for (const key of Object.keys(totals)) totals[key] += value[key];
}
const summary = {
  schema_version: 1,
  adapter: "node-test",
  test_files: policy.test_files,
  totals,
  per_file: perFile,
  status: "passed",
};
fs.writeFileSync(path.join(output, "node-test.tap"), tap.join("\n"), { mode: 0o600 });
fs.writeFileSync(path.join(output, "node-test-summary.json"), `${JSON.stringify(summary, null, 2)}\n`, {
  mode: 0o600,
});
