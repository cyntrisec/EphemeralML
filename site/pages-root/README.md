# Pages Root

This directory is the dedicated GitHub Pages source for the repository domain `ephemeralml.cyntrisec.com`.

It intentionally preserves the current public behavior:

- the repo domain redirects to `https://cyntrisec.com/docs`
- `robots.txt` remains disallowing indexing on the redirect domain
- the custom domain is carried by `CNAME`

This directory exists so the repository can stop using GitHub Pages legacy branch publishing from `main:/`.

Once the repository Pages setting is switched to **GitHub Actions**, the root web files can be removed safely.
