/* Offer or Bait? : the red-flag rules.
   Pure functions, no DOM and no network, so the same file runs in the page and in Node tests.
   analyze(text) -> { text, truncated, signals, skipped, counts, verdict }
   Each signal: { id, level: 'stop'|'warn'|'note', title, why, instead, spans: [[start, end], ...], first }
   v2 changes (after testing v1 on real scam emails and real job postings):
   - lines that warn AGAINST scams ("we will never ask you to deposit a check") no longer count as red flags
   - new: asks you to switch to a personal / non-school email; "this is not a scam" reassurance
   - weekly pay ("$600 weekly", "weekly pay of $350") and texting / Instagram contact now recognised
   - "urgent" only counts when it is about you replying or being hired, not "urgent approvals" in a job duty */
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

  // ---- warnings against scams --------------------------------------------------------------------------------------
  // Real postings often end with "We will never ask for your bank details or ask you to deposit a check."
  // A match inside a sentence like that is the company warning you, not a red flag.
  var NEG_CUE = /\b(?:never|not|no one|nobody|won't|will not|don't|do not|doesn't|does not|cannot|can't|isn't|aren't|wouldn't|would not|shouldn't|should not)\b/gi;
  var FRAUD_TALK = /\b(?:scams?|scammers?|fraud|fraudulent|fraudsters?|phishing|impersonat\w*|beware)\b/i;

  function sentenceAround(text, sp) {
    var s = sp[0];
    while (s > 0 && !/[.!?\n]/.test(text[s - 1])) s--;
    var e = sp[1];
    while (e < text.length && !/[.!?\n]/.test(text[e])) e++;
    return [s, e];
  }

  function isWarningAgainst(text, sp) {
    var se = sentenceAround(text, sp);
    var sentence = text.slice(se[0], se[1]);
    if (FRAUD_TALK.test(sentence) && !/\bnot an? scam\b/i.test(sentence)) return true;
    var before = text.slice(Math.max(se[0], sp[0] - 90), sp[0]);
    if (/\bdon'?t worry\b/i.test(before)) return false;
    NEG_CUE.lastIndex = 0;
    return NEG_CUE.test(before);
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

  // Email addresses, found by walking out from each "@" (linear time, so a huge paste can't stall the page).
  // Local parts may arrive half-redacted ("[name]@gmail.com"), so brackets are allowed before the @.
  var LOCAL_CH = /[A-Za-z0-9._%+\-\[\]{}]/, DOMAIN_CH = /[A-Za-z0-9.\-\[\]]/;

  function domainsIn(text) {
    var out = [], at = text.indexOf('@');
    while (at >= 0) {
      var a = at, b = at + 1;
      while (a > 0 && LOCAL_CH.test(text[a - 1])) a--;
      while (b < text.length && DOMAIN_CH.test(text[b])) b++;
      var domain = text.slice(at + 1, b).replace(/[\[\]]/g, '').replace(/\.+$/, '').toLowerCase();
      while (b > at + 1 && /[.\]]/.test(text[b - 1])) b--;
      if (a < at && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) out.push({ domain: domain, start: a, end: b });
      at = text.indexOf('@', at + 1);
    }
    return out;
  }

  function isOfficial(domain, list) {
    return list.some(function (d) { return domain === d || domain.slice(-(d.length + 1)) === '.' + d; });
  }

  // Pay quoted per week or per hour, in any of the shapes scam emails use.
  var MONEY = '\\$\\s?\\d[\\d,]*(?:\\.\\d+)?(?:\\s*(?:usd|dollars))?';
  var PAY_RES = [
    new RegExp(MONEY + '\\s*(?:\\/|per|an|a|each)\\s*(?:hour|hr|week|wk)\\b', 'i'),
    new RegExp(MONEY + '[^.\\n$]{0,12}?\\bweekly\\b', 'i'),
    new RegExp('\\bweekly\\b[^.$]{0,40}?' + MONEY, 'i'),
    new RegExp('\\b(?:times|days) (?:a |per )?week(?:ly)?\\b[^.\\n$]{0,12}?' + MONEY, 'i')
  ];

  // ---- the rules --------------------------------------------------------------------------------------------------
  var RULES = [
    {
      id: 'fake-check', level: 'stop', negatable: true,
      title: 'A check you deposit, then spend for them',
      why: 'The classic fake-check scam. Your bank shows the money within a day or two, but the check bounces a week or more later. Whatever you bought or sent from it is gone, and you owe the bank.',
      instead: 'never sends you money before you have worked, and never asks you to pass part of it on to a "vendor".',
      test: function (t) {
        var check = any([/\b(?:send|mail|issue|forward|courier)(?:ing)? you an? (?:e-?)?(?:check|cheque)\b/i,
          /\b(?:cashier'?s|certified|company|e-?)\s?(?:check|cheque)s?\b/i, /\bmobile deposit\b/i,
          /\bdeposit (?:the|this|your|a) (?:check|cheque)\b/i, /\bcheque\b/i], t);
        var spend = any([/\b(?:purchase|buy|order|get)(?:ing)? (?:the |your |some |all )?(?:necessary |required |needed )?(?:office |work |home[- ]office )?(?:equipment|supplies|software|laptop|computer|gift ?cards?|materials)\b/i,
          /\b(?:approved |our |designated |the )?vendor\b/i, /\bsend (?:back )?the (?:rest|remaining|balance|excess)\b/i,
          /\bremaining (?:balance|funds|amount)\b/i], t);
        return check.length && spend.length ? check.concat(spend) : null;
      }
    },
    {
      id: 'you-pay', level: 'stop', negatable: true,
      title: 'You pay to start',
      why: 'Scammers charge "training", "registration" or "starter kit" fees, then disappear or keep inventing new ones.',
      instead: 'pays for your training, equipment and background check. You never pay to get a job.',
      test: function (t) {
        var s = any([/\b(?:training|registration|application|processing|onboarding|enrol(?:l)?ment|certification|background[- ]check|equipment|starter[- ]kit|membership|placement)\s(?:fee|fees|cost|charge|deposit)s?\b/i,
          /\brefundable (?:fee|deposit)\b/i, /\b(?:pay|purchase|buy) (?:for )?(?:your|the) (?:own )?(?:starter[- ]kit|training (?:materials|kit|course)|uniform|work kit)\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'switch-email', level: 'stop', negatable: true,
      title: 'Asks you to leave your school email',
      why: 'Your school\'s email system filters scams and can trace who wrote to you. Asking for your "personal" or "alternative" address moves you somewhere nobody is watching.',
      instead: 'is happy to reach you at your school or work address, and never asks you to switch.',
      test: function (t) {
        var s = any([/\b(?:alternative|alternate|another|personal|private|non[- ]?(?:educational|school|edu|university|institutional|academic))\s+"?(?:e-?mail)(?: address)?\b/i,
          /\bnot (?:your |with your |using your )?(?:\.?edu|school|university|student|college|institutional)\s+e-?mail\b/i,
          /\b(?:e\.g\.?|i\.e\.?|such as|like)\s*,?\s*(?:yahoo|gmail|hotmail|outlook)\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'chat-app', level: 'stop', negatable: true,
      title: 'Interview by chat app or text',
      why: 'Moving you to Telegram, WhatsApp, Instagram or text keeps the conversation off the platform that could flag the account, and a text-only "interview" means nobody has to show their face.',
      instead: 'interviews you on a call or video, booked from a company address.',
      test: function (t) {
        var s = any([/\b(?:telegram|whats\s?app|wickr|google hangouts?|hangouts|kik messenger)\b/i,
          /\b(?:via|on|through|over|download) signal\b/i, /\bsignal app\b/i,
          /\b(?:text|chat|instant message|im|online chat)[- ]based interview\b/i,
          /\binterview (?:will be |is )?(?:conducted |held |done )?(?:via|over|through|by|on) (?:text|chat|instant messag\w+|im|telegram|whats\s?app|signal)\b/i,
          /\b(?:text|message|dm|contact|reach|chat with)\b[^.\n]{0,60}?\b(?:on|via|through)\s+(?:instagram|snapchat|facebook messenger|messenger|kik)\b/i,
          /\binstagram\b[^.\n]{0,40}?\bmessage only\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'sensitive', level: 'stop', negatable: true,
      title: 'Asks for ID or bank details up front',
      why: 'Your SSN, bank login or a photo of your ID is enough to open accounts in your name, or to route stolen money through you.',
      instead: 'collects payroll and tax forms after a signed offer, through a secure HR portal, not by email or chat.',
      test: function (t) {
        var s = any([/\b(?:SSN|SIN number)\b/, /\b(?:social security|social insurance) (?:number|card|no\.?)\b/i,
          /\b(?:bank|checking|savings) account (?:number|details|info(?:rmation)?)\b/i, /\brouting number\b/i,
          /\b(?:online |internet |mobile )?banking (?:login|log-in|username|password|credentials|details)\b/i,
          /\b(?:copy|photo|picture|scan) of (?:your )?(?:id|driver'?s licen[cs]e|passport|state id|id card)\b/i,
          /\b(?:credit|debit) card (?:number|details)\b/i, /\bbank details\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'mule', level: 'stop', negatable: true,
      title: 'Moving money or packages for them',
      why: '"Payment processing", "package forwarding" and crypto "task" jobs use you to launder stolen money or goods. You can be held responsible.',
      instead: 'never asks you to receive money or parcels in your own name and pass them on.',
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
      instead: 'writes from their organisation\'s own domain.',
      test: function (t) {
        var free = domainsIn(t).filter(function (d) { return FREE_MAIL.indexOf(d.domain) >= 0; });
        if (!free.length) return null;
        var role = /\b(?:recruit\w*|hiring|hr|human resources|talent|professor|prof\.|dr\.|department|faculty|university|company|corporation|inc\.?|llc|position|job|offer|intern\w*|assistant)\b/i;
        return role.test(t) ? free.map(function (d) { return [d.start, d.end]; }) : null;
      }
    },
    {
      id: 'lookalike', level: 'warn',
      title: 'A lookalike company address',
      why: 'Addresses like careers-amazon.net borrow a famous name but belong to someone else.',
      instead: 'sends from its own domain (amazon.com, google.com). Check the address character by character.',
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
      instead: 'makes an offer only after at least one live conversation, in writing from a company address.',
      test: function (t) {
        var s = any([/\bno (?:interview|experience and no interview)s? (?:is |are )?(?:required|needed|necessary)\b/i,
          /\byou (?:have been|'ve been|are|were) (?:selected|hired|approved|chosen|shortlisted) (?:for|as|to)\b/i,
          /\bwithout (?:an |any )?interview\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'too-good', level: 'warn', negatable: true,
      title: 'High pay for a few easy hours',
      why: 'Big weekly money for a few flexible hours, open to anyone, is the bait. The point is to make you skip your doubts.',
      instead: 'pays close to the going rate for the work, and says exactly what that work is.',
      test: function (t) {
        var weekly = false;
        var pay = any(PAY_RES, t).filter(function (sp) {
          var s = t.slice(sp[0], sp[1]);
          var n = parseFloat((s.match(/\$\s?(\d[\d,]*(?:\.\d+)?)/) || [0, '0'])[1].replace(/,/g, ''));
          var isWeek = /week|wk/i.test(s);
          if (isWeek && n >= 300) weekly = true;
          return isWeek ? n >= 300 : n >= 30;
        });
        if (!pay.length) return null;
        // Weekly pay is unusual in real postings, so remote / flexible framing is enough. Hourly pay needs a stronger cue.
        var easy = any([/\bno (?:prior |previous )?experience\b/i, /\bpart[- ]time\b/i, /\bat (?:your )?leisure\b/i,
          /\bset your own hours\b/i, /\bless work time\b/i, /\bwithout affecting (?:your )?(?:academic|studies|current|daily|other)\b/i,
          /\b(?:at most |only |about |just |maximum of |max(?:imum)? )?(?:\d+(?:\.\d+)?|one|two|three|four|five|six|seven|a few) hours? (?:a|per) (?:day|week)\b/i,
          /\b\d+(?:-\d+)? hours? (?:a|per) (?:day|week)\b/i, /\bfew hours\b/i]
          .concat(weekly ? [/\bflexible\b/i, /\bremote(?:ly)?\b/i, /\b(?:work|home)[- ](?:from[- ])?home\b/i, /\bfrom home\b/i] : []), t);
        return easy.length ? pay.concat(easy) : null;
      }
    },
    {
      id: 'not-a-scam', level: 'warn',
      title: 'Promises it isn\'t a scam',
      why: 'Real employers don\'t pre-empt the question. Reassurance like "100% legit" is there because the writer expects you to doubt it.',
      instead: 'lets the posting on its own careers site speak for itself.',
      test: function (t) {
        var s = any([/\b(?:this is |it'?s |it is )?not an? scam\b/i, /\b100\s?% (?:legit|legitimate|genuine|real)\b/i,
          /\blegit (?:job|offer|opportunity|company)\b/i, /\brest assured\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'vague-role', level: 'warn',
      title: 'A classic scam job title',
      why: '"Personal assistant", "mystery shopper" and "car wrap" jobs are the most common covers for fake-check scams.',
      instead: 'names the team, the manager and what you will actually do each day.',
      test: function (t) {
        var s = any([/\b(?:personal|virtual|remote|administrative) (?:assistant|personnel assistant)\b/i, /\b(?:mystery|secret) (?:shopper|evaluator)\b/i,
          /\b(?:car|vehicle) wrap\b/i, /\bdata entry\b/i, /\berrands?\b/i, /\bvirtual shopper\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'urgency', level: 'note',
      title: 'Pressure to move fast',
      why: 'Rushing you keeps you from checking. "Limited spots" and "reply within 24 hours" are there for that reason.',
      instead: 'takes days or weeks to hire, and will wait while you think.',
      test: function (t) {
        var s = any([/\burgent(?:ly)? (?:need(?:ed)?|requires?|required|hiring|position|response|reply|attention)\b/i, /\bpressing need\b/i,
          /\b(?:reply|respond|apply|contact (?:me|us)|act) (?:immediately|asap|now|today|right away|quickly)\b/i, /\basap\b/i, /\bas soon as (?:you can|possible)\b/i,
          /\bwithin (?:the next )?(?:24|48|12) hours\b/i, /\b(?:slots|spots|positions|openings) (?:are )?limited\b/i,
          /\blimited (?:slots|spots|positions|openings|vacanc\w+)\b/i, /\bact fast\b/i, /\bfirst[- ]come,? first[- ]served?\b/i,
          /\bdon'?t;? miss (?:this|out)\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'unsolicited', level: 'note',
      title: 'An offer for a job you never applied to',
      why: 'Scammers scrape emails from directories and LinkedIn, then say a "career office" or "professor" passed on your résumé.',
      instead: 'names the role and points you to a real posting to apply through.',
      test: function (t) {
        var s = any([/\b(?:found|saw|got|came across|obtained|reviewed) your (?:resume|résumé|cv|profile|email|contact)\b/i,
          /\byour (?:resume|résumé|cv|profile|email) (?:was|has been) (?:forwarded|recommended|shared|referred|passed)\b/i,
          /\b(?:career (?:center|office|services)|department) (?:forwarded|recommended|shared|referred)\b/i,
          /\byou have been offered\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'generic-greeting', level: 'note',
      title: 'Sent to a crowd, not to you',
      why: '"Dear Students" or "open to students from any department" means the same message went to thousands of addresses.',
      instead: 'uses your name and is hiring for a specific role on a specific team.',
      test: function (t) {
        var s = any([/\b(?:dear|hello|hi|greetings|attention),? (?:(?:distinguished|undergraduate|graduate|all|current) (?:and \w+ )?)?(?:students?|applicants?|candidates?|sir(?:\/| or )madam|sir|madam|user|all|beneficiary|friend|staff|faculty)\b/i,
          /\bhello dear\b/i, /\bstudents? (?:from|of|in) (?:any|all) (?:academic )?departments?\b/i, /\bany departmental student\b/i,
          /\bopen to (?:all )?students\b/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'short-link', level: 'note',
      title: 'A shortened link or form',
      why: 'bit.ly-style links and Google Forms hide who is collecting your details.',
      instead: 'takes applications through its own careers page.',
      test: function (t) {
        var s = any([/\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|goo\.gl|ow\.ly|shorturl\.at|tiny\.cc|t\.ly|forms\.gle)\/\S+/i], t);
        return s.length ? s : null;
      }
    },
    {
      id: 'off-platform', level: 'note',
      title: 'Asks you to text or share your number',
      why: 'Moving to text gets you away from email filters and the job board\'s fraud team.',
      instead: 'can book a call from the job board or their company email.',
      test: function (t) {
        var s = any([/\btext (?:me|us|him|her)\b/i, /\btext (?:my|this|the following|our) (?:number|cell|phone|mobile)\b/i,
          /\btext (?:professor|prof\.?|dr\.?|mr\.?|mrs\.?|ms\.?)\b/i, /\bvia (?:text|sms)(?: message)?\b/i, /\b(?:an? )?(?:immediate )?sms\b/i,
          /\b(?:send|reply with|provide|share|including|include) (?:me |us )?your (?:personal )?(?:cell|phone|mobile|whatsapp) (?:number|no\.?)\b/i], t);
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
    var signals = [], skipped = [];
    RULES.forEach(function (r) {
      var spans = r.test(text);
      if (!spans || !spans.length) return;
      if (r.negatable) {
        spans = spans.filter(function (sp) {
          if (!isWarningAgainst(text, sp)) return true;
          skipped.push({ id: r.id, quote: text.slice(sp[0], sp[1]) });
          return false;
        });
        if (!spans.length) return;
      }
      spans = mergeSpans(spans);
      signals.push({ id: r.id, level: r.level, title: r.title, why: r.why, instead: r.instead, spans: spans, first: spans[0][0] });
    });
    signals.sort(function (a, b) { return LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level] || a.first - b.first; });
    var counts = { stop: 0, warn: 0, note: 0 };
    signals.forEach(function (s) { counts[s.level]++; });
    return { text: text, truncated: truncated, signals: signals, skipped: skipped, counts: counts, verdict: verdictFor(counts) };
  }

  var api = { analyze: analyze, RULES: RULES, MAX_CHARS: MAX_CHARS, normalize: normalize, version: 'v2' };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.OfferOrBait = api;
})(this);
