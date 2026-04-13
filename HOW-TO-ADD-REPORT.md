# How to Add a New Report

Follow these 3 steps every time you want to publish a new report.

---

## Step 1 — Copy the template

```
cp reports/report-template.html reports/your-report-slug.html
```

Use a short, lowercase, hyphenated name for the slug.
Example: `reports/redline-stealer-analysis.html`

---

## Step 2 — Edit the report HTML

Open `reports/your-report-slug.html` and fill in:

| Section | What to change |
|---|---|
| `<title>` | Your report title |
| `tag-pill` class | `tag-malware` / `tag-threat` / `tag-vuln` / `tag-apt` |
| Date | `2025-04-13` format |
| Read time | e.g. `10 MIN READ` |
| Severity badge | `sev-crit` / `sev-high` / `sev-med` |
| Report title h1 | Your actual title |
| Summary blockquote | 2-3 sentence executive summary |
| Section content | Your full analysis |
| IOC table rows | Real hashes, IPs, domains |
| YARA rule | Your detection rule |

---

## Step 3 — Register it in reports-data.js

Open `assets/js/reports-data.js` and add one object to the `REPORTS` array:

```js
{
  slug:     "redline-stealer-analysis",   // filename without .html
  title:    "RedLine Stealer: Full Unpacking & String Decryption",
  date:     "2025-04-13",
  tag:      "MALWARE",                    // MALWARE | THREAT | VULN | APT
  severity: "HIGH",                       // CRITICAL | HIGH | MEDIUM | LOW
  readTime: "12 MIN READ",
  excerpt:  "Manual unpacking of a packed RedLine sample with YARA rule.",
  // Optional: IOCs for the IOC Feed page
  iocs: [
    { type: "SHA256", indicator: "aabbcc...ddeeff", family: "RedLine", confidence: "HIGH" },
    { type: "IP",     indicator: "1.2.3.4",          family: "RedLine", confidence: "HIGH" },
    { type: "DOMAIN", indicator: "evil[.]com",        family: "RedLine", confidence: "MEDIUM" },
  ],
},
```

---

## Step 4 — Deploy to GitHub

```bash
git add .
git commit -m "Add report: RedLine Stealer analysis"
git push
```

Your report will be live in ~30 seconds at:
`https://yourusername.github.io/secblog/reports/redline-stealer-analysis.html`

---

## First-time GitHub Pages setup

1. Go to your repo on GitHub
2. Settings → Pages
3. Source: **Deploy from a branch**
4. Branch: **main** / root folder
5. Save — your site will be live at `https://yourusername.github.io/secblog/`

---

## Personalise your blog (do this once)

Edit `assets/js/config.js`:

```js
authorName:     "Your Real Name",
initials:       "AB",
certifications: ["OSCP", "GREM"],
skills:         ["Reverse Engineering", "DFIR"],
links: {
  twitter:  "https://twitter.com/yourhandle",
  github:   "https://github.com/yourusername",
  email:    "mailto:you@example.com",
},
```
