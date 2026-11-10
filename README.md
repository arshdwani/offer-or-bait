# Offer or Bait?

**Live:** https://arshdwani.github.io/offer-or-bait/

Paste a job message you got (email, text, DM). Offer or Bait? highlights the lines a scammer would write, says why
scammers write them and what a real employer does instead, and gives you a safe reply to send back.

- 17 plain rules for the patterns the FTC and university fraud offices warn about: fake checks, fees to start,
  chat-app interviews, ID or bank details up front, money or package forwarding, personal or lookalike email
  addresses, requests to move to your personal email or to text, weekly pay for a few easy hours, and pressure.
- Runs entirely in your browser. No AI, no server, no storage; the page's Content-Security-Policy blocks all
  network requests. Refreshing clears what you pasted.
- Phrases inside a warning *against* scams ("we will never ask you to deposit a check") are skipped, and the result
  says which ones.

## Tested on real messages

| Real messages | v1 | v2 |
|---|---|---|
| Job postings called "Bait." (128 postings, 16 companies' Greenhouse boards) | 16 | 0 |
| Scam emails called "Bait." or "Probably bait." (48, Cornell IT Phish Bowl 2024-25, used to fix v1) | 6 | 37 |
| Scam emails with "No usual red flags" (same 48) | 25 | 3 |
| Held-out scam emails called "Bait." or "Probably bait." (9 from 2026, unseen while fixing) | 2 | 7 |

What broke in v1 and what v2 changed is in the v2 commit message. Limits: the scam emails come from one university
and many share one template; some have addresses redacted and two have no text at all. Job postings are not recruiter
emails. Plain rules can be beaten by rewording, so the page says "signals, not proof".

## Files

- `rules.js`: every check, as pure functions (`analyze(text)`), shared by the page and the tests
- `app.js`, `index.html`, `style.css`: the page
- `tests/`: `node --test tests/`

Made by Arshd Wani.
