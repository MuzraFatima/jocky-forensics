# Performance Pass

What was checked, what changed, and what does not apply to a lab prototype that is not deployed as a
production service.

| Item | Result |
|---|---|
| Cache API responses | Technique registry, detection rules, platform info and collector list send `Cache-Control: private, max-age=300` |
| Server-side caching / cache expensive queries | Live timeline, analysis and correlation share one collection per source for 15 s (`JOCKY_LIVE_CACHE_SECONDS`); concurrent requests wait for the one in flight. Script execution and evidence sealing always collect fresh |
| N+1 queries | The process collector called `ppid()` per process, which on Windows rebuilds the whole process table each time, and re-read every access-denied field. One parent map per snapshot and no re-reads: about 4.6 s to about 2.1 s on the lab machine |
| Index the database | No database. Evidence files were found by a recursive search on every lookup; both stores now keep an ID-to-path index (400 lookups: about 840 ms to about 46 ms) |
| Paginate large lists | `GET /api/forensics/vault/list?limit=&offset=` (newest first; totals still cover every artifact). The audit log already takes `limit` |
| Compress API payloads | `GZipMiddleware` for responses over 1 KB |
| Split code into chunks / lazy loading | Command search, endpoints, reports, techniques and support load on first visit. First download went from one 106 KB gzipped bundle to 38 KB of app code plus a separately cached 59 KB vendor chunk |
| Loading skeletons | `Skeleton.jsx` placeholders while a screen's code loads, so the layout does not jump |
| Debounce input handlers | The six list search boxes (processes, network, files, services, correlation, timeline) filter on a 200 ms debounced value |
| Unnecessary re-renders | Process and network filters memoised; the sidebar gets stable props and `React.memo`, so typing elsewhere no longer re-renders it |
| Minify JS and CSS | Already done by Vite's production build |
| Defer non-critical scripts | Google Fonts no longer block first paint (preload, then apply); app scripts are ES modules, which are deferred by default |
| Unused dependencies | `depcheck` finds none in the frontend. Backend test tools (pytest, httpx) moved out of the runtime requirements into `requirements-dev.txt` |
| Lighthouse audit | Sign-in page, production build: Performance 93, Accessibility 100, Best Practices 96, SEO 100 (from 95 / 81 / 93 / 91). Fixed contrast, small text, touch-target size, robots.txt and favicon |
| Compress images | Not applicable: the app ships no raster images (one SVG favicon) |
| Load balancer | Skipped: not deployed as a multi-instance service |
| Add CDN | Skipped: not deployed. The Netlify preview already serves static files from a CDN |
| Database connection pooling | Not applicable: no database. The endpoint agent already reuses one HTTP session |

The Lighthouse pass also found a real bug: the dashboard's start-up requests ran on the login page and
never again after sign-in, so the dashboard opened empty. They now start once a session exists.
