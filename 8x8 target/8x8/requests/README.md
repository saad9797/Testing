# Saved Requests/Responses

Drop raw HTTP traffic here so it can be read back and diffed later:

- Burp: right-click a request → Save item(s), or export a whole sitemap branch
- curl transcripts: `curl -v ... > requests/<short-name>.txt 2>&1` (keep `-v` so headers are captured)
- Browser: DevTools → Network tab → right-click a request → Copy → Copy as cURL, paste into a `.sh` file here

Naming convention: `<host>__<endpoint-slug>__<what-youre-testing>.txt`
e.g. `user-profile.8x8.com__get-profile-by-id__idor-test.txt`

Keep request/response pairs together in one file so a diff between "my account" and
"someone else's ID" is easy to read in one place.
