# How to Add a Sigma Rule

Sigma rules live on the **SIGMA RULES** tab of `detections.html`.

---

## Step 1 — Add it

Open `detections.html?tab=sigma` → **＋ ADD SIGMA RULE**, paste the rule's YAML
(or attach the `.yml` file) and, if the write-up already exists, its report slug.

Everything else is read from the YAML itself:

| Shown on the page | Read from |
|---|---|
| Title, description, author, date | `title`, `description`, `author`, `date` |
| Level badge | `level` (informational / low / medium / high / critical) |
| Log source chip | `logsource` → `product · category · service` |
| ATT&CK chips (link to attack.mitre.org) | `tags` such as `attack.t1059.001` |

The rule must have a `title`, a `logsource:` block and a `detection:` block with a `condition:`.
It is saved in **your browser only** at this point (marked `LOCAL ONLY`).

---

## Step 2 — Publish it

1. On the Sigma tab click **⬇ export sigma-data.js**
2. Replace `assets/js/sigma-data.js` with the downloaded file
3. `git add . && git commit -m "add sigma rule" && git push`

Leave the report slug empty if there's no report yet — the rule shows **NO REPORT YET**.
When the write-up is ready, set `report: "my-report-slug"` on the entry in `sigma-data.js`.

---

## Attach a rule straight to a report (optional)

In `reports-data.js`, next to `yara: [...]`:

```js
sigma: [
  { rule: `title: Suspicious Encoded PowerShell
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: ' -enc '
    condition: selection
level: high` }
],
```

It appears on the Sigma tab linked to that report automatically.
