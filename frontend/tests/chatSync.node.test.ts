import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mergeLocalEntries, type LocalEntryLike } from '../src/services/chatSync.ts';

type M = LocalEntryLike & { text: string };
const srv = (id: string): M => ({ id, text: id });
const local = (id: string, status: 'sending' | 'delivered' | 'failed', scope = 'dm|bob'): M => ({
  id,
  text: id,
  sendStatus: status,
  localScope: scope,
});

describe('chat sync: merging server messages with local (optimistic) entries', () => {
  it('keeps a message that is still sending after a reload that does not contain it yet', () => {
    const out = mergeLocalEntries([srv('a')], [srv('a'), local('x', 'sending')], 'dm|bob');
    assert.deepEqual(out.map((m) => m.id), ['a', 'x']);
  });

  it('replaces the optimistic entry with the real one (no duplicate) once the server has it', () => {
    const out = mergeLocalEntries([srv('a'), srv('x')], [srv('a'), local('x', 'delivered')], 'dm|bob');
    assert.deepEqual(out.map((m) => m.id), ['a', 'x']);
    assert.equal(out[1].sendStatus, undefined); // the server copy wins
  });

  it('keeps a just-delivered message visible if the reload raced ahead of the server insert', () => {
    const out = mergeLocalEntries([srv('a')], [local('x', 'delivered')], 'dm|bob');
    assert.deepEqual(out.map((m) => m.id), ['a', 'x']);
  });

  it('keeps failed entries (so the Retry button survives background syncs)', () => {
    const out = mergeLocalEntries([], [local('f', 'failed')], 'dm|bob');
    assert.deepEqual(out.map((m) => m.id), ['f']);
  });

  it('never leaks local entries of another conversation', () => {
    const out = mergeLocalEntries([srv('a')], [local('x', 'sending', 'groups|g1')], 'dm|bob');
    assert.deepEqual(out.map((m) => m.id), ['a']);
  });

  it('returns the server list unchanged when there is nothing local', () => {
    const server = [srv('a'), srv('b')];
    assert.equal(mergeLocalEntries(server, [srv('a')], 'dm|bob'), server);
  });

  it('preserves send order: server messages first, then still-pending local ones in the order sent', () => {
    const out = mergeLocalEntries(
      [srv('a')],
      [local('p1', 'sending'), local('p2', 'sending')],
      'dm|bob'
    );
    assert.deepEqual(out.map((m) => m.id), ['a', 'p1', 'p2']);
  });
});
