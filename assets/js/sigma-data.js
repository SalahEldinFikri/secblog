// ============================================================
//  SIGMA-DATA.JS — one entry per published Sigma rule
// ============================================================
//
//  HOW IT WORKS
//  1. Open detections.html → the "SIGMA RULES" tab → "＋ ADD SIGMA RULE".
//     Paste (or attach) the rule's YAML. The title, level, log source and
//     ATT&CK tags are read straight from the YAML.
//     It is saved in YOUR BROWSER so you can check how it looks.
//  2. To publish it for visitors click "⬇ export sigma-data.js"
//     on that tab, replace THIS file with the download, then
//     git add, git commit, git push — done!
//
//  A rule with  report: ""  shows "NO REPORT YET".
//  When the write-up is ready set  report: "my-report-slug"
//  (the file name in reports/ without .html).
//
//  You can also attach rules straight to a report in reports-data.js:
//     sigma: [ { rule: "title: ...\nlogsource: ...\n..." } ]
//
//  ENTRY SHAPE
//  {
//    slug:        "suspicious-powershell-encoded",   // unique, a-z 0-9 and dashes
//    title:       "Suspicious Encoded PowerShell",
//    description: "Detects powershell launched with -enc",
//    author:      "SalahEldin Kamil (Mr_MaTriX)",
//    date:        "2026-10-24",
//    level:       "high",                            // informational | low | medium | high | critical
//    status:      "experimental",                    // stable | test | experimental | deprecated
//    logsource:   { product: "windows", category: "process_creation", service: "" },
//    tags:        ["attack.execution", "attack.t1059.001"],
//    report:      "",                                // "" = no report yet
//    rule:        "title: ...\nlogsource:\n  ...\n"  // the full Sigma YAML
//  }
//
// ============================================================

const SIGMA_RULES = [

];
