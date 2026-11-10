// Run: node --test tests/
const test = require('node:test');
const assert = require('node:assert');
const OB = require('../rules.js');
const ids = (t) => OB.analyze(t).signals.map((s) => s.id);
const verdict = (t) => OB.analyze(t).verdict.key;

test('fake check with a vendor is a stop sign', () => {
  const t = 'I will mail you a check for $2,850. Keep $400 and use the rest to buy office supplies from our approved vendor.';
  assert.ok(ids(t).includes('fake-check'));
  assert.strictEqual(verdict(t), 'bait');
});

test('a company warning against scams is not held against it', () => {
  const t = 'Acme will never ask for your Social Security number or bank details, and we will never ask you to deposit a check or purchase equipment.';
  const r = OB.analyze(t);
  assert.strictEqual(r.verdict.key, 'clear');
  assert.ok(r.skipped.length >= 3);
});

test('fraud notices mentioning chat apps are skipped', () => {
  const t = 'Beware of scammers posing as our recruiters on WhatsApp or Telegram.';
  assert.strictEqual(verdict(t), 'clear');
});

test('"don\'t worry" does not hide a real ask', () => {
  const t = "Don't worry, just deposit the check and buy the equipment from our vendor.";
  assert.ok(ids(t).includes('fake-check'));
});

test('asking for a non-school email is a stop sign', () => {
  assert.ok(ids('Reply with your alternative email address (e.g., Yahoo, Gmail) and not your EDU email.').includes('switch-email'));
  assert.ok(ids('Contact the professor WITH YOUR PERSONAL “Email Address”.').includes('switch-email'));
});

test('weekly pay in the shapes scam emails use', () => {
  for (const t of ['They work remotely and get paid $600 Weekly.', 'Tasks take 1 hour per day with a weekly pay of $350.',
    'Weekly Salary:\n$400 for remote admin duties', 'earn $500.00 USD weekly, flexible hours']) {
    assert.ok(ids(t).includes('too-good'), t);
  }
});

test('normal intern pay is not "too good"', () => {
  assert.ok(!ids('The internship is paid $48/hour and based in our Seattle office.').includes('too-good'));
  assert.ok(!ids('Salary range: $120,000 - $160,000 per year. Hybrid, 3 days a week in office.').includes('too-good'));
});

test('texting a professor on Instagram is a chat-app interview', () => {
  assert.ok(ids("If you're interested kindly Text Professor Smith on Instagram (prof.smith) message Only.").includes('chat-app'));
});

test('"urgent approvals" in a job duty is not pressure', () => {
  assert.ok(!ids('You will know how to obtain urgent approvals and input from stakeholders.').includes('urgency'));
  assert.ok(ids('There is a pressing need for assistants. Slots are limited.').includes('urgency'));
});

test('lookalike and free-mail addresses', () => {
  assert.ok(ids('Recruiter, Amazon: hr@amazon-careers-hiring.com').includes('lookalike'));
  assert.ok(!ids('Recruiter, Amazon: jane@amazon.com').includes('lookalike'));
  assert.ok(ids('Professor Adler, Department of Biology: kraig.adler8@gmail.com').includes('free-mail'));
});

test('empty, huge and odd input', () => {
  assert.strictEqual(verdict(''), 'clear');
  assert.strictEqual(verdict(null), 'clear');
  const big = OB.analyze('x'.repeat(OB.MAX_CHARS + 50));
  assert.ok(big.truncated);
  assert.strictEqual(big.text.length, OB.MAX_CHARS);
  assert.doesNotThrow(() => OB.analyze('$-50 per hour \u{1F600} <script>alert(1)</script> $abc weekly'));
});

test('spans always point inside the text', () => {
  const t = 'Dear Students, earn $650 Weekly. Text me. Send a copy of your ID. bit.ly/x1';
  const r = OB.analyze(t);
  for (const s of r.signals) for (const [a, b] of s.spans) assert.ok(a >= 0 && b <= r.text.length && a < b);
});
