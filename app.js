/* Offer or Bait? : page wiring. All analysis is in rules.js. Nothing is stored or sent. */
(function () {
  'use strict';
  var OB = window.OfferOrBait;
  var $ = function (id) { return document.getElementById(id); };
  var msg = $('msg'), result = $('result'), err = $('err');
  var checkedOnce = false, timer = null;

  var EXAMPLES = {
    check: 'Hello Student,\n\nYour resume was forwarded to us by the career center. Dr. Helen Marsh of the Department of Biology is looking for a remote personal assistant. It\'s part-time, about 4 hours a week, and pays $400 per week. No interview is required.\n\nTo begin, I will mail you a check for $2,850. Keep $400 as your first week\'s pay and use the rest to buy office supplies from our approved vendor. Text me at (555) 013-2291 once you have deposited the check. Please reply within 24 hours as spots are limited.\n\nDr. Helen Marsh\nhelen.marsh.biolab@gmail.com',
    chat: 'Hi there! I\'m Jessica, a talent recruiter with Amazon. We came across your profile and you have been shortlisted for a Remote Data Entry Clerk role ($38/hr, flexible hours, no experience needed).\n\nThe interview will be conducted via Telegram. Download Telegram and message our hiring manager @AmzHR_Daniel to begin.\n\nOnboarding is fast: send a copy of your driver\'s license and your bank account number for direct deposit.\n\nJessica Moore\nhr@amazon-careers-hiring.com',
    real: 'Hi Priya,\n\nThanks for applying to the Software Engineering Intern (Summer 2027) role on our careers site. I\'d like to set up a 30-minute video call with two engineers on the team next week to talk about your robotics project and the role. Reply with a few times that work, or pick one from the scheduling page in your candidate portal.\n\nThe internship is paid ($42/hour), based in our Austin office, and runs 12 weeks from June to August. One note: Fernhill will never ask you to pay a fee, deposit a check or share bank details during hiring.\n\nBest,\nMarcus Lee\nUniversity Recruiting, Fernhill Robotics\nmarcus.lee@fernhillrobotics.com'
  };

  var REPLY = 'Hi, thanks for reaching out. Before we go further, could you:\n\n1. Send me the link to this role on your company\'s own careers site,\n2. Email me from your company address, and\n3. Set up a short video call with the hiring manager?\n\nI don\'t interview over chat apps, and I don\'t handle payments, checks or equipment purchases for employers.\n\nThanks!';

  var STEPS = {
    bait: [
      'Stop replying in that thread.',
      'Don\'t deposit any check, and don\'t send money, gift cards or crypto.',
      'Don\'t send your ID, Social Security number or bank details.',
      'Look the company up yourself and contact it through its official website, not the links or numbers in the message.',
      'Report the message to the job board or school email it came through, and tell your career office.',
      'Already sent money or details? Call your bank now, then report it at reportfraud.ftc.gov (US) or your country\'s fraud line.'
    ],
    likely: [
      'Don\'t send money, ID or bank details yet.',
      'Search for the company yourself and find this role on its own careers site.',
      'Send the safe reply below and see whether they can answer it.',
      'Unsure? Forward it to your school\'s career office before you reply.'
    ],
    check: [
      'Find this role on the company\'s own careers site.',
      'Check that the sender\'s address matches the company\'s real domain.',
      'If anything feels off, send the safe reply below.'
    ],
    clear: [
      'Still apply through the company\'s own careers site.',
      'Never pay, deposit a check or buy equipment to get a job, at any stage.'
    ]
  };

  function esc(s) {
    return s.replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; });
  }

  // Each character belongs to at most one signal: the most serious one (signals arrive sorted by level).
  // Badges are numbered in reading order, so the marked-up message reads 1, 2, 3 from the top.
  function markup(text, signals, num) {
    var owner = new Array(text.length);
    signals.forEach(function (s, i) {
      s.spans.forEach(function (sp) {
        for (var k = sp[0]; k < sp[1]; k++) if (owner[k] === undefined) owner[k] = i;
      });
    });
    var html = '', i = 0, numbered = {};
    while (i < text.length) {
      var o = owner[i], j = i;
      while (j < text.length && owner[j] === o) j++;
      var chunk = esc(text.slice(i, j));
      if (o === undefined) html += chunk;
      else {
        var s = signals[o], n = num[o];
        html += '<mark class="hl hl-' + s.level + '" tabindex="0" data-n="' + n + '" title="' + esc(s.title) + '">' + chunk + '</mark>';
        if (!numbered[n]) { numbered[n] = true; html += '<span class="n ' + s.level + '" aria-hidden="true">' + n + '</span>'; }
      }
      i = j;
    }
    return html;
  }

  function quotes(text, s) {
    var seen = {}, out = [];
    s.spans.forEach(function (sp) {
      var q = text.slice(sp[0], sp[1]).replace(/\s+/g, ' ').trim();
      var key = q.toLowerCase();
      if (q && !seen[key] && out.length < 3) { seen[key] = true; out.push(q.length > 80 ? q.slice(0, 77) + '...' : q); }
    });
    return out;
  }

  var GROUPS = [
    { level: 'stop', head: 'Stop signs', sub: 'Patterns that on their own mean a scam.' },
    { level: 'warn', head: 'Warnings', sub: 'Common in scams, rare in real offers.' },
    { level: 'note', head: 'Worth noticing', sub: 'Weak on their own, telling together.' }
  ];

  function card(r, s, n) {
    var q = quotes(r.text, s).map(function (x) { return '"' + esc(x) + '"'; }).join(' · ');
    return '<li class="sig ' + s.level + '" id="sig-' + n + '">' +
      '<div class="sig-head"><span class="n ' + s.level + '">' + n + '</span><h3>' + esc(s.title) + '</h3></div>' +
      '<p class="quote">' + q + '</p>' +
      '<p>' + esc(s.why) + '</p>' +
      '<p class="instead"><b>A real employer</b> ' + esc(s.instead) + '</p></li>';
  }

  function noteRow(r, s, n) {
    var q = quotes(r.text, s)[0] || '';
    return '<li id="sig-' + n + '" class="note-row"><span class="n note">' + n + '</span><div><b>' + esc(s.title) + '</b>' +
      ' <span class="quote">"' + esc(q) + '"</span><p>' + esc(s.why) + '</p></div></li>';
  }

  function render(r) {
    var v = $('verdict');
    v.className = 'verdict ' + r.verdict.key;
    $('vWord').textContent = r.verdict.word;
    $('vLine').textContent = r.verdict.line;
    var c = r.counts, pills = [];
    if (c.stop) pills.push('<span class="pill stop">' + c.stop + ' stop sign' + (c.stop > 1 ? 's' : '') + '</span>');
    if (c.warn) pills.push('<span class="pill warn">' + c.warn + ' warning' + (c.warn > 1 ? 's' : '') + '</span>');
    if (c.note) pills.push('<span class="pill note">' + c.note + ' worth noticing</span>');
    $('vCounts').innerHTML = pills.join('');

    // reading-order numbers
    var order = r.signals.map(function (s, i) { return i; }).sort(function (a, b) { return r.signals[a].first - r.signals[b].first; });
    var num = []; order.forEach(function (idx, k) { num[idx] = k + 1; });

    $('trunc').hidden = !r.truncated;
    if (r.truncated) $('trunc').textContent = 'Only the first ' + OB.MAX_CHARS.toLocaleString() + ' characters were checked.';
    $('letter').innerHTML = markup(r.text, r.signals, num);

    var html = '';
    GROUPS.forEach(function (g) {
      var items = r.signals.map(function (s, i) { return { s: s, n: num[i] }; })
        .filter(function (x) { return x.s.level === g.level; })
        .sort(function (a, b) { return a.n - b.n; });
      if (!items.length) return;
      html += '<section class="group ' + g.level + '"><h3 class="g-head">' + g.head + ' <span>' + g.sub + '</span></h3>';
      if (g.level === 'note') {
        html += '<ul class="sig notes">' + items.map(function (x) { return noteRow(r, x.s, x.n); }).join('') + '</ul>';
      } else {
        html += '<ol class="signals">' + items.map(function (x) { return card(r, x.s, x.n); }).join('') + '</ol>';
      }
      html += '</section>';
    });
    $('sigHead').textContent = r.signals.length ? 'What each highlight means' : 'Nothing highlighted';
    $('signals').innerHTML = html || '<p class="none">None of the checks matched this message.</p>';

    // Lines where the sender warns you about scams are not held against them. Say so, so a clean result is explained.
    var sk = $('skipped');
    if (r.skipped.length) {
      var uniq = [], seen = {};
      r.skipped.forEach(function (x) { var k = x.quote.toLowerCase(); if (!seen[k]) { seen[k] = 1; uniq.push(x.quote); } });
      sk.innerHTML = '<b>Not counted:</b> ' + uniq.length + ' phrase' + (uniq.length > 1 ? 's' : '') +
        ' inside a warning against scams, like "we will never ask you to..." (' +
        uniq.slice(0, 4).map(function (q) { return '"' + esc(q) + '"'; }).join(', ') + (uniq.length > 4 ? ', ...' : '') + ').';
      sk.hidden = false;
    } else sk.hidden = true;

    $('steps').innerHTML = STEPS[r.verdict.key].map(function (t) { return '<li>' + esc(t) + '</li>'; }).join('');
    $('replyText').value = REPLY;
    result.hidden = false;
  }

  function run(scroll) {
    var text = msg.value;
    if (!text.trim()) {
      err.textContent = 'Paste a message first, or tap one of the examples below.';
      err.hidden = false; result.hidden = true; msg.focus();
      return;
    }
    err.hidden = true;
    render(OB.analyze(text));
    checkedOnce = true;
    if (scroll) $('verdict').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  $('go').addEventListener('click', function () { run(true); });
  msg.addEventListener('keydown', function (e) { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') run(true); });
  msg.addEventListener('input', function () {
    if (!checkedOnce) return;
    clearTimeout(timer);
    timer = setTimeout(function () { if (msg.value.trim()) run(false); }, 250);
  });

  Array.prototype.forEach.call(document.querySelectorAll('.chip'), function (b) {
    b.addEventListener('click', function () { msg.value = EXAMPLES[b.getAttribute('data-ex')]; run(true); });
  });

  function jump(el) {
    var card = $('sig-' + el.getAttribute('data-n'));
    if (!card) return;
    card.scrollIntoView({ behavior: 'smooth', block: 'center' });
    card.classList.add('flash');
    setTimeout(function () { card.classList.remove('flash'); }, 1200);
  }
  $('letter').addEventListener('click', function (e) { var m = e.target.closest('mark'); if (m) jump(m); });
  $('letter').addEventListener('keydown', function (e) {
    var m = e.target.closest('mark'); if (m && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); jump(m); }
  });

  $('copy').addEventListener('click', function () {
    var btn = this, ta = $('replyText');
    function done() { btn.textContent = 'Copied'; setTimeout(function () { btn.textContent = 'Copy reply'; }, 1500); }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(ta.value).then(done, fallback);
    else fallback();
    function fallback() { ta.select(); try { document.execCommand('copy'); done(); } catch (e) { btn.textContent = 'Select the text and copy it'; } }
  });

  $('again').addEventListener('click', function () {
    msg.value = ''; result.hidden = true; checkedOnce = false; err.hidden = true;
    window.scrollTo({ top: 0, behavior: 'smooth' }); msg.focus();
  });

  $('ver').textContent = OB.version;
  $('ruleCount').textContent = OB.RULES.length;

  // ?example=check|chat|real loads an example (used for screenshots and demo links).
  var ex = new URLSearchParams(location.search).get('example');
  if (ex && EXAMPLES[ex]) { msg.value = EXAMPLES[ex]; run(false); }
  var th = new URLSearchParams(location.search).get('theme');
  if (th === 'light' || th === 'dark') document.documentElement.setAttribute('data-theme', th);
})();
