# How to Add a Standalone YARA Rule

A **standalone** rule is a YARA rule that isn't part of a report. (Rules written inside a report
live in `reports-data.js` as `yara: [...]` and are counted with that report.)

---

## Step 1 — Add it

Open `detections.html` → **YARA RULES** tab → **＋ ADD RULE**, fill in the name, description and
the rule (it must contain a `condition:` block), then **SAVE RULE**.

Straight away, in your browser:

- the rule appears at the top of the YARA feed (marked `LOCAL ONLY`)
- the **YARA Rules Written** counter on the homepage goes up by one
- the YARA tab badge and the stats row update

---

## Step 2 — Publish it (this is what puts it in the data file)

A website can't write to your repo by itself, so the rule goes into the data file like this:

1. When you save, an updated **`yara-data.js`** is downloaded automatically
   (untick *"Also download the updated yara-data.js when I save"* in the form to turn this off — the choice is remembered).
   You can also click **⬇ export yara-data.js** on the YARA tab at any time.
2. Replace `assets/js/yara-data.js` with the downloaded file
3. `git add . && git commit -m "add yara rule" && git push`

Once that's pushed, the rule shows for every visitor and the homepage counter counts it for everyone
(until then it only counts in the browser you added it in).

> The exported file contains **all** standalone rules — the ones already published plus the ones you
> added — so always replace the whole file rather than editing it by hand.

---

## Deleting a rule

- A rule that's only in your browser: **DELETE** on its card.
- A published rule: remove its entry from `assets/js/yara-data.js` and push.
