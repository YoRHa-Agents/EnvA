#!/usr/bin/env node

const { spawnSync } = require("node:child_process");

const packages = {
  "linux-x64": "@yorha-agents/enva-linux-x64",
  "linux-arm64": "@yorha-agents/enva-linux-arm64",
  "darwin-arm64": "@yorha-agents/enva-darwin-arm64",
};
const key = `${process.platform}-${process.arch}`;
const packageName = packages[key];

if (!packageName) {
  console.error(`@yorha-agents/enva does not support ${key}.`);
  process.exit(1);
}

let binary;
try {
  binary = require.resolve(`${packageName}/bin/enva`);
} catch {
  console.error(`The native package ${packageName} is not installed for ${key}.`);
  console.error(`Try reinstalling @yorha-agents/enva on a supported platform.`);
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  console.error(`Failed to start Enva: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
