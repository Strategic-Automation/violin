# Website development

The public landing page is `index.html`. GitHub Pages can serve it directly;
Vite is development tooling only, with no client-side framework or runtime dependency.

From this directory, using Node 22.12 or newer:

```sh
npm ci
npm run dev
npm run build
```

The build writes `dist/`. Do not commit generated output or `node_modules/`.

Before changing public claims, run the repository's landing-page contracts:

```sh
cd ..
uv run pytest tests/test_landing_page.py tests/test_release_links.py
```

Review at 320, 390, 768, 1024, and desktop widths. Check installation tabs with
arrow keys, Home, and End; copy feedback; navigation dismissal with Escape;
all guard scenarios; search with and without results; category filters; FAQ
disclosures; and keyboard scrolling inside the two data tables. The demo is
illustrative and must never be presented as a live execution or benchmark.
