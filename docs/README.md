# Website development

The public homepage is `index.html`. Detailed content lives on `guide.html`,
`guard.html`, `coverage.html`, `tools.html`, `engineering.html`, and `review.html`. Shared
styles and behavior live in `assets/site.css` and `assets/site.js`; simulation
and filtering scripts load only on their respective pages.

GitHub Pages can serve these files directly;
Vite is development tooling only, with no client-side framework or runtime dependency.

From this directory, using Node 22.12 or newer:

```sh
npm ci
npm run dev
npm run build
```

The build writes all seven page entry points to `dist/`. Do not commit generated
output or `node_modules/`. Keep the homepage short; put reference material in
the docs. The website contracts enforce a 350-word homepage budget and check
local destinations and copyable commands as well as the public inventories.

Before changing public claims, run the repository's landing-page contracts:

```sh
cd ..
uv run pytest tests/test_landing_page.py tests/test_release_links.py
```

Review at 320, 390, 768, 1024, and desktop widths. Check installation tabs with
arrow keys, Home, and End; copy feedback; navigation dismissal with Escape;
all guard scenarios; search with and without results; category filters; FAQ
disclosures; tool descriptions; the collapsed architecture comparison; and
navigation between pages. Check old homepage fragment links such as `#how`
and `#playbooks`, which redirect to their new documentation destinations. The demo is
illustrative and must never be presented as a live execution or benchmark.
