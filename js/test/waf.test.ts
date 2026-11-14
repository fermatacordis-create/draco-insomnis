import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { inspect, flatten, type WafInput } from '../src/core/waf.ts';

// The same cases as the PHP tests (tests/vectors/waf.json): both languages must agree.
const vectors = JSON.parse(readFileSync(fileURLToPath(new URL('../../tests/vectors/waf.json', import.meta.url)), 'utf8')) as {
  attacks: { name: string; request: WafInput; rule: string }[];
  ordinary: { name: string; request: WafInput }[];
};

for (const v of vectors.attacks) {
  test(`attack: ${v.name}`, () => assert.equal(inspect(v.request), v.rule));
}
for (const v of vectors.ordinary) {
  test(`ordinary: ${v.name}`, () => assert.equal(inspect(v.request), null));
}

test('flatten', () => {
  assert.deepEqual(flatten({ a: 1, b: { c: 2 } }), ['a', '1', 'b', 'c', '2']);
  assert.equal(flatten([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 3).length, 3);
});
