// ============================================================
//  REPORTS-DATA.JS — Add a new entry here for each report
// ============================================================
//
//  HOW TO ADD A REPORT:
//  1. Copy report-template.html → reports/my-report-slug.html
//  2. Edit that HTML file with your content
//  3. Add one entry to the REPORTS array below
//  4. git add, git commit, git push  — done!
//
// ============================================================

const REPORTS = [

  // ── EXAMPLE ENTRY (delete this when you add your first real one) ──
  // {
  //   slug:     "agenttesla-xor-c2",           // filename without .html
  //   title:    "AgentTesla Variant with XOR-Encrypted C2",
  //   date:     "2025-04-13",
  //   tag:      "MALWARE",                      // MALWARE | THREAT | VULN | APT
  //   severity: "HIGH",                         // CRITICAL | HIGH | MEDIUM | LOW
  //   readTime: "12 MIN READ",
  //   excerpt:  "A new AgentTesla sample with a custom XOR encryption layer over its C2 channel.",
  // },

  // ── YOUR REPORTS ────────────────────────────────────────────────

  {
    slug: "adobe-reader-zerodday",
    title: "Adobe Reader Zero-Day: Malicious PDF with Embedded JavaScript & Multi-Stage Payload",
    date: "2026-04-07",
    tag: "VULN",
    severity: "CRITICAL",
    readTime: "14 MIN READ",
    excerpt: "Analysis of a malicious PDF exploiting an Adobe Reader zero-day. JSFuck obfuscation, hidden AcroForm payload, AES-CTR decryption, and covert C2 via abused PDF RSS APIs.",
    iocs: [
      { type: "IP", indicator: "169.40.2.68:45191", family: "AdobeReaderZeroDay", confidence: "HIGH" },
    ],
  },

  {
    slug: "evelyn-stealer",
    title: "Evelyn Stealer: Threat Analysis of a Developer-Focused Stealer Campaign",
    date: "2026-01-31",
    tag: "MALWARE",
    severity: "CRITICAL",
    readTime: "15 MIN READ",
    excerpt: "Multi-stage stealer targeting software developers via malicious VS Code extensions. Uses DLL hijacking, process hollowing into grpconv.exe, and headless browser abuse to harvest credentials, crypto wallets, and Telegram sessions.",
    iocs: [
      { type: "SHA256", indicator: "369479bd9a248c9448705c222d81ff1a0143343a138fc38fc0ea00f54fcc1598", family: "EvelynStealer", confidence: "HIGH" },
      { type: "SHA256", indicator: "e77bdfcc5bb6c120f2eb60cdffbe247ae2a09c9043640bfdd34d6e412782eec8", family: "EvelynStealer", confidence: "HIGH" },
      { type: "DOMAIN", indicator: "syn1112223334445556667778889990[.]org", family: "EvelynStealer", confidence: "HIGH" },
      { type: "DOMAIN", indicator: "server09.mentality.cloud", family: "EvelynStealer", confidence: "HIGH" },
    ],
  },

  {
    slug: "stealc-worm",
    title: "Inside a Windows Worm: How It Spreads, Persists, and Steals Cryptocurrency",
    date: "2026-02-10",
    tag: "MALWARE",
    severity: "HIGH",
    readTime: "12 MIN READ",
    excerpt: "Stealc-family Windows worm spreading via USB, network shares, and local directories. Deploys COM-based persistence, registry file-association hijacking, and a cryptocurrency clipboard hijacker targeting BTC, ETH, and TRON.",
    iocs: [
      { type: "SHA256", indicator: "aad0a60cb86e3a56bcd356c6559b92c4dc4a1a960f409fb499cf76c9b5409fdb", family: "StealcWorm", confidence: "HIGH" },
      { type: "IP", indicator: "62.60.226.159", family: "StealcWorm", confidence: "HIGH" },
    ],
  },

  {
    slug: "kalim-backdoor",
    title: "Kalim Backdoor Malware Analysis Report",
    date: "2025-08-01",
    tag: "APT",
    severity: "CRITICAL",
    readTime: "18 MIN READ",
    excerpt: "64-bit DLL backdoor attributed to MuddyWater. Establishes persistence via COM-based startup shortcut, then performs host fingerprinting, encrypted C2 comms with moodleuni[.]com, remote shell execution, and HTTPS data exfiltration.",
    iocs: [
      { type: "SHA256", indicator: "0c8071494bc155c96f2cee998200f63efffcb5a064c021de0925504271806229", family: "Kalim", confidence: "HIGH" },
      { type: "DOMAIN", indicator: "moodleuni[.]com", family: "Kalim", confidence: "HIGH" },
      { type: "IP", indicator: "150.171.27.12", family: "Kalim", confidence: "MEDIUM" },
    ],
  },

];
