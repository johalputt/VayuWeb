import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:net';

import { EgressRefused, dial } from './egress.ts';

/** A listener that counts the connections it accepted, so "no socket was opened" is observable. */
async function listener(): Promise<{ port: number; accepted: () => number; close: () => void }> {
  let count = 0;
  const server: Server = createServer((socket) => {
    count += 1;
    socket.destroy();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('the listener has no address');
  }
  return {
    port: address.port,
    accepted: () => count,
    close: () => server.close(),
  };
}

test('a private-mode resolver refuses to open a socket, and opens none', () => {
  // PRIVACY.md 3.1 and 3.3: in Private Mode the anonymising transport is mandatory, and when it
  // is unavailable the resolver refuses. No fallback, no queue, no prompt, no degradation.
  //
  // The observable is the connection count, not the promise. A refusal that still opened the
  // socket and then closed it would reject the promise and leak the connection, and the shape of
  // the error would not show it.
  return listener().then(async (server) => {
    try {
      await assert.rejects(
        () => dial('peer', { host: '127.0.0.1', port: server.port }, 'private'),
        (error: unknown) => {
          assert.ok(error instanceof EgressRefused, `expected a refusal, got ${String(error)}`);
          // The message says what was refused and why, and it does not offer a way round it.
          assert.match(error.message, /Private Mode/);
          assert.match(error.message, /3\.3/);
          assert.doesNotMatch(error.message, /continue anyway/i);
          return true;
        },
      );
      // Give the event loop a turn: a socket opened and closed in the same tick would still
      // have reached the listener by now.
      await new Promise((resolve) => setTimeout(resolve, 50));
      assert.equal(server.accepted(), 0, 'the refusal must not have opened a socket');
    } finally {
      server.close();
    }
  });
});

test('a clearnet resolver dials through the choke point', async () => {
  // The guard is not a wall: in Standard Mode the socket is opened, and the point of the choke
  // point is that this is the one function that opens it.
  const server = await listener();
  try {
    const socket = await dial('replication', { host: '127.0.0.1', port: server.port }, 'clearnet');
    assert.ok(socket, 'the dial resolved with a socket');
    socket.destroy();
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(server.accepted(), 1, 'the socket reached the listener');
  } finally {
    server.close();
  }
});

test('the refusal names the purpose it was refusing', async () => {
  // A refusal that does not say what was refused is a refusal an operator cannot act on, and
  // the purpose is the thing that tells them which subsystem wanted the byte.
  await assert.rejects(
    () => dial('fetch', { host: '127.0.0.1', port: 1 }, 'private'),
    (error: unknown) => {
      assert.ok(error instanceof EgressRefused);
      assert.equal(error.purpose, 'fetch');
      assert.match(error.message, /fetch socket/);
      return true;
    },
  );
});

test('a dial that cannot connect fails as a failure and not as a refusal', () => {
  // The two are different facts. A refusal is a decision; a connection error is a fact about the
  // network. Code that catches one as the other will offer a reader the wrong thing.
  return assert.rejects(
    () => dial('peer', { host: '127.0.0.1', port: 1 }, 'clearnet'),
    (error: unknown) => {
      assert.ok(
        !(error instanceof EgressRefused),
        `a failed dial is not a refusal: ${String(error)}`,
      );
      return true;
    },
  );
});
