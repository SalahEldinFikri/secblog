# How to Add an Extractor

An **extractor** is a YARA rule + extractor code (+ the IOCs and config it pulled out).
You can publish it **before** the report is written — it shows up on the Extractors page,
its IOCs go to the IOC feed, and the homepage announces it in the **New Drop** box.

---

## Step 1 — Add it on the Extractors page

Open `extractors.html` → **＋ ADD EXTRACTOR** and fill in:

| Field | Notes |
|---|---|
| Name, Malware family | required |
| YARA rule | paste it, or attach the `.yar` file |
| Extractor code | required — paste it, or attach the `.py` file |
| IOCs & configuration | attach the `.json` you saved after running the extractor |
| Report slug | **leave empty** if there's no report yet |

It's saved in **your browser only** at this point, so you can check how it looks
(marked `LOCAL ONLY`). The IOCs already appear on `ioc-feed.html` in your browser.

### JSON formats accepted

```json
{
  "iocs": [
    { "type": "DOMAIN", "indicator": "c2.example.com", "family": "MyFamily", "confidence": "HIGH" }
  ],
  "config": { "c2": ["c2.example.com:443"], "mutex": "Global\\abc" }
}
```

Also accepted: a **cfgx** result (`{ "status": "...", "config": [...] }`), a cfgx batch report,
or a plain list of IOCs. If the file has no `iocs`, IPs / URLs / domains found inside `config`
are added as `MEDIUM` confidence (untick the box in the form to turn this off).
There's a **Download a template** link in the form.

---

## Step 2 — Publish it

1. On the Extractors page click **⬇ export extractors-data.js**
2. Replace `assets/js/extractors-data.js` with the downloaded file
3. `git add . && git commit -m "add extractor" && git push`

Visitors now see it, its IOCs are on the IOC feed, and — because `report` is empty —
the homepage **New Drop** box announces it.

---

## Step 3 — When the report is ready

Open `assets/js/extractors-data.js`, find the entry and set the report slug:

```js
report: "vortex-stealer",   // file name in reports/ without .html
```

Commit and push. The entry now links to the report and leaves the **New Drop** box.
