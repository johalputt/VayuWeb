#!/usr/bin/env -S node --experimental-strip-types
/**
 * Entry point. Kept to three lines so that everything testable lives in src/cli.ts and the
 * process boundary is the only thing this file owns.
 */
import { main } from '../src/cli.ts';

const result = main(process.argv.slice(2));
// `serve` is long-running and therefore the one command that returns a promise. Awaiting it here
// rather than making every command async keeps the other fifteen synchronous and testable as
// plain calls.
process.exitCode = typeof result === 'number' ? result : await result;
