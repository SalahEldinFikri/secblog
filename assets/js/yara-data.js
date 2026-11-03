// ============================================================
//  YARA-DATA.JS — standalone YARA rules (rules that are not tied to a report)
// ============================================================
//
//  HOW IT WORKS
//  1. Open detections.html → the "YARA RULES" tab → "＋ ADD RULE".
//     Fill in the form and save. The rule shows up on the page and is
//     counted in the homepage "YARA Rules Written" counter in YOUR browser
//     straight away.
//  2. To make it count for everyone, publish it: when you save, an updated
//     copy of THIS file is downloaded for you (or click
//     "⬇ export yara-data.js" on the tab at any time).
//     Replace this file with the download, then
//     git add, git commit, git push — done!
//
//  Rules written inside a report (the  yara: [...]  array in reports-data.js)
//  don't go here — they are already counted with their report.
//
//  ENTRY SHAPE
//  {
//    id:          "mirai_elf_variant",              // unique, made from the name
//    name:        "Mirai_ELF_Variant",
//    description: "Detects a Mirai ELF variant",
//    author:      "SalahEldin Kamil (Mr_MaTriX)",
//    tag:         "MALWARE",                        // MALWARE | APT | THREAT | VULN | TOOL | CUSTOM
//    reference:   "",                               // optional link / hash
//    date:        "2026-10-24",
//    rule:        "rule Mirai_ELF_Variant { ... }"
//  }
//
// ============================================================

const YARA_RULES = [

];
