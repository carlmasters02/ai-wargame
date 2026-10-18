# Security Policy

AI Wargame is a simulation: it never touches real systems, and the "attacks" are
moves in a game engine. The server itself is still a web application, so
vulnerabilities in it are taken seriously.

## Reporting a vulnerability

Please **don't open a public issue** for a security problem. Report it privately
through GitHub instead:
[**Report a vulnerability**](https://github.com/carlmasters02/ai-wargame/security/advisories/new),
or by email to **carl.masters.dev@protonmail.com**.

Include what you found, how to reproduce it (a request, payload or import file is
ideal), and the impact you expect. This is a personal project maintained on a
best-effort basis. Reports are acknowledged as soon as possible, and fixes land
on `main`. Only the latest `main` is supported.

## Security model

What the server protects, and what it deliberately doesn't:

- **Local-only by default.** With `WARGAME_TOKEN` unset, the server serves only
  connections from the same machine (loopback) addressed to `localhost`, and
  refuses proxied requests (`X-Forwarded-For` / `Forwarded` / `X-Real-IP`).
  Exposing it on a network or behind a reverse proxy requires a token; the Docker
  image generates one at start-up if none is set.
- **Controls need the token.** Every state-changing endpoint requires the
  `X-Wargame-Token` header when a token is set. The page reads it once from
  `#token=…` in its URL; the fragment never reaches the server or its logs.
- **No cross-site control.** `POST` requests and WebSocket upgrades whose
  `Origin` differs from the server's host are refused (CSRF and cross-site
  WebSocket hijacking). Responses carry a strict Content-Security-Policy and
  can't be framed.
- **Imports are untrusted.** CSV, Nmap XML (parsed with `defusedxml`) and
  BloodHound JSON are size-capped, host, edge and vulnerability counts are
  limited, and names are reduced to a safe character set before they reach the
  UI, the reports or the LLM prompts. Attack-path analysis has a fixed work
  budget, so a crafted network can't exhaust the CPU.
- **Model output is untrusted.** LLM agents pick only from a numbered list of
  legal actions. The after-action report is sanitised with DOMPurify before it
  is rendered, and the executive report is HTML-escaped on the server.

**By design, not vulnerabilities:**

- **Spectating is public.** The page, `/ws` and `GET` endpoints need no token
  and show the full "god view" of the simulated network. The data is synthetic
  (or a network you chose to import). Don't import a real network into a server
  that people you don't trust can reach.
- **Replay mode** (`python -m app.replay`) is read-only and binds to
  `127.0.0.1` unless you pass `--host`.
- **No TLS or rate limiting is built in.** Put the server behind a reverse proxy
  that handles both if you expose it, and set `WARGAME_TOKEN`. A proxy that hides
  the client address (no forwarding headers) looks like a local connection.

API keys (`AIAND_API_KEY`, `MODEL_PROVIDERS`) live only in your local `.env`,
which is git-ignored. They are never sent to the browser.
