/* Offer or Bait? : the red-flag rules.
   Pure functions, no DOM and no network, so the same file runs in the page and in Node tests.
   analyze(text) -> { signals, verdict, counts }
   Each signal: { id, level: 'stop'|'warn'|'note', title, why, instead, spans: [[start, end], ...] } */
(function (root) {
  'use strict';

  var MAX_CHARS = 20000;

  // Curly quotes and dashes become plain ones. Same length, so match positions still line up with the original.
  function normalize(text) {
    return text.replace(/[‘’ʼ]/g, "'").replace(/[“”]/g, '"')
      .replace(/[–—]/g, '-').replace(/ /g, ' ');
  }

  function findAll(re, text) {
    var spans = [], m, flags = re.flags.indexOf('g') < 0 ? re.flags + 'g' : re.flags;
    var g = new RegExp(re.source, flags);
    while ((m = g.exec(text)) !== null) {
      if (m[0].length === 0) { g.lastIndex++; continue; }
      spans.push([m.index, m.index + m[0].length]);
    }
    return spans;
  }

  function any(res, text) {
    var out = [];
    res.forEach(function (re) { out = out.concat(findAll(re, text)); });
    return out;
  }

  // ---- shared word lists --------------------------------------------------------------------------------------
  var FREE_MAIL = ['gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'outlook.com', 'hotmail.com', 'live.com',
    'msn.com', 'aol.com', 'icloud.com', 'me.com', 'mail.com', 'gmx.com', 'gmx.net', 'proton.me', 'protonmail.com',
    'pm.me', 'yandex.com', 'yandex.ru', 'tutanota.com', 'zohomail.com', 'inbox.com', 'mail.ru', 'qq.com', '163.com'];

  // Employers students hear from most, with the domains they actually send from.
  var BRANDS = {
    amazon: ['amazon.com', 'amazon.jobs', 'amazon.co.uk', 'amazon.in', 'aboutamazon.com'],
    google: ['google.com', 'alphabet.com'], microsoft: ['microsoft.com'], apple: ['apple.com'],
    facebook: ['fb.com', 'facebook.com', 'meta.com', 'metacareers.com'], netflix: ['netflix.com'],
    tesla: ['tesla.com'], nvidia: ['nvidia.com'], oracle: ['oracle.com'], salesforce: ['salesforce.com'],
    adobe: ['adobe.com'], intel: ['intel.com'], cisco: ['cisco.com'], deloitte: ['deloitte.com'],
    accenture: ['accenture.com'], jpmorgan: ['jpmorgan.com', 'jpmchase.com', 'jpmorganchase.com'],
    goldman: ['gs.com', 'goldmansachs.com'], morganstanley: ['morganstanley.com'],
    bankofamerica: ['bankofamerica.com', 'bofa.com'], wellsfargo: ['wellsfargo.com'], capitalone: ['capitalone.com'],
    paypal: ['paypal.com'], uber: ['uber.com'], airbnb: ['airbnb.com'], spotify: ['spotify.com'],
    walmart: ['walmart.com', 'walmart.org'], target: ['target.com'], costco: ['costco.com'],
    starbucks: ['starbucks.com'], pfizer: ['pfizer.com'], boeing: ['boeing.com'], spacex: ['spacex.com'],
    linkedin: ['linkedin.com'], indeed: ['indeed.com'], handshake: ['joinhandshake.com'], disney: ['disney.com'],
    nike: ['nike.com'], pepsico: ['pepsico.com'], mckinsey: ['mckinsey.com'], verizon: ['verizon.com'],
    fedex: ['fedex.com'], samsung: ['samsung.com'], shopify: ['shopify.com'], stripe: ['stripe.com'],
    coinbase: ['coinbase.com'], ibm: ['ibm.com']
  };

  var EMAIL_RE = /[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/g;
  var URL_RE = /\b(?:https?:\/\/)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:\/[^\s)]*)?/gi;

  function domainsIn(text) {
    var out = [], m;
    var e = new RegExp(EMAIL_RE.source, 'g');
    while ((m = e.exec(text)) !== null) {
      out.push({ domain: m[1].toLowerCase(), start: m.index, end: m.index + m[0].length, email: true });
    }
    return out;
  }

  function isOfficial(domain, list) {
    return list.some(function (d) { return domain === d || domain.slice(-(d.length + 1)) === '.' + d; });
  }

  // ---- the rules --------------------------------------------------------------------------------------------------
  var RULES = [
    {
      id: 'fake-check', level: 'stop',
      title: 'A check you deposit, then spend for them',
      why: 'The classic fake-check scam. Your bank shows the money within a day or two, but the check bounces a week or more later. Whatever you bought or sent from it is gone, and you owe the bank.',
      instead: 'A real employer never sends you money before you have worked, and never asks you to pass part of it on to a "vendor".',
      test: function (t) {
        var check = any([/\b(?:send|mail|issue|forward)(?:ing)? you an? (?:e-?)?(?:check|cheque)\b/i,
          /\b(?:cashier'?s|certified|company|e-?)\s?(?:check|cheque)s?\b/i, /\bmobile deposit\b/i,
          /\bdeposit (?:the|this|your|a) (?:check|cheque)\b/i, /\bcheque\b/i], t);
        var spend = any([/\b(?:purchase|buy|order)(?:ing)? (?:the |your |some )?(?:equipment|supplies|software|laptop|computer|office|gift ?cards?)\b/i,
          /\b(?:approved |our |designated )?vendor\b/i, /\bsend (?:back )?the (?:rest|remaining|balance|excess)\b/i,
          /\bremaining (?:balance|funds|amount)\b/i], t);
        return check.length && spend.length ? check.concat(spend) : null;
      }
    },
    {
      id: 'you-pay', level: 'stop',
      title: 'You pay to start',
      why: 'Scammers charge "training", "registration" or "starter kit" fees, then disappear or keep inventing new ones.',
      instead: 'Real employers pay for your training, equipment and background check. You never pay to get a job.',
      test: function (t) {
        var s = any([/\b(?:training|registration|application|processing|onboarding|enrol(?:l)?ment|certification|background[- ]check|equipment|starter[- ]kit|membership|placement)\s(?:fee|fees|cost|charge|deposit)s?\b/i,
          /\brefundable (?:fee|deposit)\b/i, /\b(?:pay|purchase|buy) (?:for )?(?:your|the) (?:own )?(?:starter[- ]kit|training (?:materials|kit|course)|uniform|work kit)\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'chat-app', level: 'stop',
      title: 'Interview by chat app or text',
      why: 'Moving you to Telegram, WhatsApp, Signal or text keeps the conversation off the platform that could flag the account, and a text-only "interview" means nobody has to show their face.',
      instead: 'Real interviews happen on a call or video, booked from a company address.',
      test: function (t) {
        var s = any([/\b(?:telegram|whats\s?app|wickr|google hangouts?|hangouts|kik messenger)\b/i,
          /\b(?:via|on|through|over|download) signal\b/i, /\bsignal app\b/i,
          /\b(?:text|chat|instant message|im|online chat)[- ]based interview\b/i,
          /\binterview (?:will be |is )?(?:conducted |held |done )?(?:via|over|through|by|on) (?:text|chat|instant messag\w+|im|telegram|whats\s?app|signal)\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'sensitive', level: 'stop',
      title: 'Asks for ID or bank details up front',
      why: 'Your SSN, bank login or a photo of your ID is enough to open accounts in your name, or to route stolen money through you.',
      instead: 'Payroll and tax forms come after a signed offer, through a secure HR portal, not by email or chat.',
      test: function (t) {
        var s = any([/\b(?:social security|SSN|social insurance number|SIN number)\b/, /\bsocial security\b/i,
          /\b(?:bank|checking|savings) account (?:number|details|info(?:rmation)?)\b/i, /\brouting number\b/i,
          /\b(?:online |internet |mobile )?banking (?:login|log-in|username|password|credentials|details)\b/i,
          /\b(?:copy|photo|picture|scan) of (?:your )?(?:id|driver'?s licen[cs]e|passport|state id|id card)\b/i,
          /\b(?:credit|debit) card (?:number|details)\b/i, /\bbank details\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'mule', level: 'stop',
      title: 'Moving money or packages for them',
      why: '"Payment processing", "package forwarding" and crypto "task" jobs use you to launder stolen money or goods. You can be held responsible.',
      instead: 'No real job asks you to receive money or parcels in your own name and pass them on.',
      test: function (t) {
        var s = any([/\b(?:re-?ship(?:ping)?|package (?:forwarding|handler|inspector|reshipping)|parcel forwarding)\b/i,
          /\b(?:receive|process|transfer) (?:payments|funds|transfers) (?:for|on behalf of)\b/i,
          /\b(?:payment|financial|funds?) (?:processing )?(?:agent|representative|coordinator)\b/i,
          /\b(?:usdt|crypto(?:currency)?|bitcoin|btc) (?:deposit|top[- ]?up|recharge)\b/i,
          /\b(?:deposit|top[- ]?up|recharge) (?:to )?(?:unlock|continue|start) (?:the )?(?:tasks?|orders?|work)\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'free-mail', level: 'warn',
      title: 'Personal email for a company or university job',
      why: 'Anyone can make a Gmail called "hr.department.recruiting". Scammers use them to pose as companies, and as professors offering "assistant" jobs.',
      instead: 'Recruiters and professors write from their organisation\'s own domain.',
      test: function (t) {
        var free = domainsIn(t).filter(function (d) { return FREE_MAIL.indexOf(d.domain) >= 0; });
        if (!free.length) return null;
        var role = /\b(?:recruit\w*|hiring|hr|human resources|talent|professor|prof\.|dr\.|department|faculty|university|company|corporation|inc\.?|llc|position|job|offer)\b/i;
        return role.test(t) ? free.map(function (d) { return [d.start, d.end]; }) : null;
      }
    },
    {
      id: 'lookalike', level: 'warn',
      title: 'A lookalike company address',
      why: 'Addresses like careers-amazon.net borrow a famous name but belong to someone else.',
      instead: 'Big employers send from their own domain (amazon.com, google.com). Check the address character by character.',
      test: function (t) {
        var spans = [];
        domainsIn(t).forEach(function (d) {
          Object.keys(BRANDS).forEach(function (b) {
            if (d.domain.replace(/[-.]/g, '').indexOf(b) >= 0 && !isOfficial(d.domain, BRANDS[b])) spans.push([d.start, d.end]);
          });
        });
        return spans.length ? spans : null;
      }
    },
    {
      id: 'no-interview', level: 'warn',
      title: 'Hired without an interview',
      why: 'An offer before anyone has spoken to you is how scams skip the step where they would be found out.',
      instead: 'Real offers follow at least one live conversation, and come in writing from a company address.',
      test: function (t) {
        var s = any([/\bno (?:interview|experience and no interview)s? (?:is |are )?(?:required|needed|necessary)\b/i,
          /\byou (?:have been|'ve been|are|were) (?:selected|hired|approved|chosen|shortlisted) (?:for|as|to)\b/i,
          /\bwithout (?:an |any )?interview\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'too-good', level: 'warn',
      title: 'High pay for easy, part-time work',
      why: 'Big money for a few flexible hours with no experience is the bait. The point is to make you skip your doubts.',
      instead: 'Entry-level part-time pay is usually close to local minimum wage, and the posting says what the work actually is.',
      test: function (t) {
        var pay = findAll(/\$\s?\d[\d,]*(?:\.\d+)?\s*(?:usd\s*)?(?:\/|per|an|a|each)\s*(?:hour|hr|week|wk)\b/i, t).filter(function (sp) {
          var s = t.slice(sp[0], sp[1]);
          var n = parseFloat(s.replace(/[^\d.]/g, ''));
          return /week|wk/i.test(s) ? n >= 300 : n >= 30;
        });
        var easy = any([/\bno (?:prior |previous )?experience\b/i, /\bpart[- ]time\b/i, /\bflexible (?:hours|schedule)\b/i,
          /\b(?:a few|\d|two|three) hours (?:a|per) (?:day|week)\b/i], t);
        return pay.length && easy.length ? pay.concat(easy) : null;
      }
    },
    {
      id: 'vague-role', level: 'warn',
      title: 'A classic scam job title',
      why: '"Personal assistant", "mystery shopper" and "car wrap" jobs are the most common covers for fake-check scams.',
      instead: 'Real postings name the team, the manager and what you will actually do each day.',
      test: function (t) {
        var s = any([/\b(?:personal|virtual|remote|administrative) assistant\b/i, /\b(?:mystery|secret) shopper\b/i,
          /\b(?:car|vehicle) wrap\b/i, /\bdata entry\b/i, /\berrands?\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'urgency', level: 'note',
      title: 'Pressure to move fast',
      why: 'Rushing you keeps you from checking. "Limited spots" and "reply within 24 hours" are there for that reason.',
      instead: 'Real hiring takes days or weeks, and a recruiter will wait while you think.',
      test: function (t) {
        var s = any([/\burgent(?:ly)?\b/i, /\bimmediately\b/i, /\basap\b/i, /\bwithin (?:the next )?(?:24|48|12) hours\b/i,
          /\blimited (?:slots|spots|positions|openings|vacanc\w+)\b/i, /\bact fast\b/i, /\bfirst come,? first served\b/i,
          /\b(?:respond|reply) (?:now|today|right away)\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'unsolicited', level: 'note',
      title: 'An offer for a job you never applied to',
      why: 'Scammers scrape emails from directories and LinkedIn, then say a "career office" or "professor" passed on your résumé.',
      instead: 'If a recruiter found you, they will name the role and point you to a real posting to apply through.',
      test: function (t) {
        var s = any([/\b(?:found|saw|got|came across|obtained|reviewed) your (?:resume|résumé|cv|profile|email|contact)\b/i,
          /\byour (?:resume|résumé|cv|profile|email) (?:was|has been) (?:forwarded|recommended|shared|referred|passed)\b/i,
          /\b(?:career (?:center|office|services)|department) (?:forwarded|recommended|shared|referred)\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'generic-greeting', level: 'note',
      title: 'Not addressed to you',
      why: '"Dear Student" means the same message went to thousands of addresses.',
      instead: 'A recruiter who picked you uses your name.',
      test: function (t) {
        var s = any([/\b(?:dear|hello|hi|attention) (?:students?|applicants?|candidates?|sir(?:\/| or )madam|sir|madam|user|all|beneficiary|friend)\b/i,
          /\bhello dear\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'short-link', level: 'note',
      title: 'A shortened link',
      why: 'bit.ly-style links hide where they go, which is handy for fake application forms that collect your details.',
      instead: 'Search for the company yourself and apply through its own careers page.',
      test: function (t) {
        var s = any([/\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|goo\.gl|ow\.ly|shorturl\.at|tiny\.cc|t\.ly)\/\S+/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'off-platform', level: 'note',
      title: 'Asks you to text or share your number',
      why: 'Moving to text gets you away from email filters and the job board\'s fraud team.',
      instead: 'A recruiter can book a call from the job board or their company email.',
      test: function (t) {
        var s = any([/\btext (?:me|us|him|her)\b/i, /\btext (?:my|this|the following|our) (?:number|cell|phone|mobile)\b/i,
          /\b(?:send|reply with|provide|share) (?:me |us )?your (?:personal )?(?:cell|phone|mobile|whatsapp) (?:number|no\.?)\b/i], t);
        return s.length ? s : null;
      }
    }
  ];

  var LEVEL_ORDER = { stop: 0, warn: 1, note: 2 };

  function mergeSpans(spans) {
    var s = spans.slice().sort(function (a, b) { return a[0] - b[0] || b[1] - a[1]; }), out = [];
    s.forEach(function (sp) {
      var last = out[out.length - 1];
      if (last && sp[0] <= last[1]) last[1] = Math.max(last[1], sp[1]); else out.push(sp.slice());
    });
    return out;
  }

  function verdictFor(counts) {
    if (counts.stop > 0) return { key: 'bait', word: 'Bait.', line: 'This matches a known job-scam pattern. Don\'t send money, deposit anything, or share ID or bank details.' };
    if (counts.warn >= 2 || (counts.warn === 1 && counts.note >= 2)) return { key: 'likely', word: 'Probably bait.', line: 'Several red flags together. Verify the company yourself before you reply.' };
    if (counts.warn === 1 || counts.note >= 1) return { key: 'check', word: 'Check first.', line: 'A few things to verify before you share anything.' };
    return { key: 'clear', word: 'No usual red flags.', line: 'None of the common scam patterns showed up. That is not proof it is real, so still apply through the company\'s own site.' };
  }

  function analyze(input) {
    var raw = String(input == null ? '' : input);
    var truncated = raw.length > MAX_CHARS;
    var text = normalize(truncated ? raw.slice(0, MAX_CHARS) : raw);
    var signals = [];
    RULES.forEach(function (r) {
      var spans = r.test(text);
      if (spans && spans.length) {
        signals.push({ id: r.id, level: r.level, title: r.title, why: r.why, instead: r.instead, spans: mergeSpans(spans) });
      }
    });
    signals.sort(function (a, b) { return LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level] || a.spans[0][0] - b.spans[0][0]; });
    var counts = { stop: 0, warn: 0, note: 0 };
    signals.forEach(function (s) { counts[s.level]++; });
    return { text: text, truncated: truncated, signals: signals, counts: counts, verdict: verdictFor(counts) };
  }

  var api = { analyze: analyze, RULES: RULES, MAX_CHARS: MAX_CHARS, normalize: normalize, version: 'v1' };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.OfferOrBait = api;
})(this);
