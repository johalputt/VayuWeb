#!/usr/bin/env -S node --experimental-strip-types
/**
 * Entry point. Kept to three lines so that everything testable lives in src/cli.ts and the
 * process boundary is the only thing this file owns.
 */
import { main } from '../src/cli.ts';

process.exitCode = main(process.argv.slice(2));
