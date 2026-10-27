// ============================================================
//  EXTRACTORS-DATA.JS — one entry per published extractor
// ============================================================
//
//  HOW IT WORKS
//  1. Open detections.html → the "EXTRACTORS" tab and click "＋ ADD EXTRACTOR".
//     Fill in the form, attach your YARA rule + extractor code, and
//     (optionally) the .json file with the IOCs / config you extracted.
//     It is saved in YOUR BROWSER so you can check how it looks.
//  2. To publish it for visitors click "⬇ export extractors-data.js"
//     on that tab, replace THIS file with the download, then
//     git add, git commit, git push — done!
//
//  WHAT HAPPENS AUTOMATICALLY
//  • Every entry's `iocs` are merged into the IOC feed (ioc-feed.html).
//  • An entry with  report: ""  (no report yet) is announced in the
//    "New Drop" box on the homepage, next to Featured Expedition.
//  • When the write-up is ready, set  report: "my-report-slug"
//    (the file name in reports/ without .html). The announcement
//    disappears and the entry links to the report instead.
//
//  ENTRY SHAPE
//  {
//    slug:        "voidstealer-config",          // unique, a-z 0-9 and dashes
//    name:        "VoidStealer Config Extractor",
//    family:      "VoidStealer",
//    date:        "2026-10-23",
//    author:      "SalahEldin Kamil (Mr_MaTriX)",
//    description: "Pulls the Steam ID and C2 list out of VoidStealer samples.",
//    report:      "",                            // "" = no report yet
//    yara:        { name: "VoidStealer", rule: "rule VoidStealer { ... }" },   // or null
//    extractor:   { filename: "voidstealer_extractor.py", language: "python", code: "..." },
//    iocs:        [ { type: "DOMAIN", indicator: "c2.example.com", family: "VoidStealer", confidence: "HIGH" } ],
//    config:      { c2: ["c2.example.com"], mutex: "Global\\abc" }   // anything, or null
//  }
//
// ============================================================

const EXTRACTORS = [

];
