# SecBlog — Cybersecurity & Malware Analysis Blog

A dark-themed static blog for publishing malware analysis reports, threat intelligence, and IOC feeds. Runs entirely on GitHub Pages — no backend, no CMS, no database.

## Quick Start

1. Fork or clone this repo
2. Edit `assets/js/config.js` with your name, bio, and links
3. Push to GitHub and enable GitHub Pages (Settings → Pages → main branch)

## Adding Reports

See [HOW-TO-ADD-REPORT.md](HOW-TO-ADD-REPORT.md) for the full guide.

Short version:
```bash
cp reports/report-template.html reports/my-new-report.html
# edit the HTML
# add entry to assets/js/reports-data.js
git add . && git commit -m "Add report" && git push
```

## Structure

```
secblog/
├── index.html              Homepage
├── reports.html            All reports + filter
├── ioc-feed.html           Aggregated IOC table + CSV export
├── about.html              Author page
├── reports/
│   ├── report-template.html  Copy this for each new report
│   └── *.html               Your actual reports
├── assets/
│   ├── css/
│   │   ├── style.css        Global styles
│   │   └── report.css       Report page styles
│   └── js/
│       ├── config.js        ← EDIT THIS — your name/bio/links
│       ├── reports-data.js  ← EDIT THIS — one entry per report
│       └── *.js             Page logic
└── HOW-TO-ADD-REPORT.md    Step-by-step guide
```

## License

Content © you. Code: MIT.
