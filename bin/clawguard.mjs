#!/usr/bin/env node
import { runCli } from "../src/cli.mjs";

const code = runCli(process.argv.slice(2));
process.exit(code);
