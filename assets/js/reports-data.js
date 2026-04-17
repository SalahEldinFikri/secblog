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
    date: "2026-04-15",
    tag: "VULN",
    severity: "CRITICAL",
    readTime: "14 MIN READ",
    excerpt: "Analysis of a malicious PDF exploiting an Adobe Reader zero-day. JSFuck obfuscation, hidden AcroForm payload, AES-CTR decryption, and covert C2 via abused PDF RSS APIs.",
    iocs: [
      { type: "SHA256", indicator: "65dca34b04416f9a113f09718cbe51e11fd58e7287b7863e37f393ed4d25dde7", family: "PDF Sample AdobeReaderZeroDay", confidence: "HIGH" },
      { type: "IP", indicator: "169.40.2.68:45191", family: "C2 AdobeReaderZeroDay", confidence: "HIGH" },
      { type: "URL", indicator: "http://169.40.2.68:45191/&lt;path&gt;?language=&viewerType=&version=&platform=&...", family: "C2 AdobeReaderZeroDay", confidence: "HIGH" },
    ],
    yara: null,
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
      { type: "SHA256", indicator: "369479bd9a248c9448705c222d81ff1a0143343a138fc38fc0ea00f54fcc1598", family: "LightShot.dll", confidence: "HIGH" },
      { type: "SHA256", indicator: "e77bdfcc5bb6c120f2eb60cdffbe247ae2a09c9043640bfdd34d6e412782eec8", family: "EvelynStealer", confidence: "HIGH" },
      { type: "DOMAIN", indicator: "syn1112223334445556667778889990[.]org", family: "EvelynStealer", confidence: "HIGH" },
      { type: "DOMAIN", indicator: "server09.mentality.cloud", family: "C2 EvelynStealer", confidence: "HIGH" },
    ],
    yara: [
      {
        name: "Evelyn_Injector",
        description: "Detects Evelyn Stealer injector (runtime.exe)",
        author: "SalahEldin Fikri (Mr_MaTriX)",
        rule: "rule Evelyn_Injector\n{\n    meta:\n        description = \"Detects Evelyn Stealer injector (runtime.exe)\"\n        author      = \"SalahEldin Fikri (Mr_MaTriX)\"\n    strings:\n        $s1  = \"[*] Process Hollowing Complete!\"\n        $s2  = \"[*] Resume Thread!\"\n        $s3  = \"[*] Destination process created!\"\n        $s4  = \"[*] Decrypting embedded payload...\"\n        $s5  = \"[-] Failed writing header!\"\n        $s6  = \"[-] Failed unmapping target ImageBase!\"\n        $s7  = \"[*] Successfully loaded all required APIs\"\n    condition:\n        uint16(0) == 0x5A4D and filesize < 500KB and 5 of ($s*)\n}",
      },
      {
        name: "Evelyn_Stealer",
        description: "Detects Evelyn Stealer payload",
        author: "SalahEldin Fikri (Mr_MaTriX)",
        rule: "rule Evelyn_Stealer\n{\n    meta:\n        description = \"Detects Evelyn Stealer payload\"\n        author      = \"SalahEldin Fikri (Mr_MaTriX)\"\n    strings:\n        $m1 = \"[-] All upload attempts failed - data saved locally in Evelyn folder\"\n        $m2 = \"[*] Starting Evelyn Browser Extractor...\"\n        $m3 = \"[-] ERROR: Failed to create Evelyn folder\"\n        $s1 = \"[*] Downloading abe_decrypt.dll from FTP server...\"\n        $s2 = \"abe_decrypt.dll\" wide\n        $s3 = \"[*] Stealing Telegram session...\"\n        $s4 = \"[*] Stealing Steam session...\"\n        $s5 = \"[*] Capturing screenshot...\"\n        $s6 = \"[*] Killing existing browser processes...\"\n        $s7 = \"[+] WiFi profiles stolen successfully\"\n    condition:\n        uint16(0) == 0x5A4D and filesize < 300KB and (any of ($m*)) and (5 of ($s*))\n}",
      },
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
      { type: "IP", indicator: "62.60.226.159", family: "C2 StealcWorm", confidence: "HIGH" },
    ],
    yara: null,
  },

  {
    slug: "kalim-backdoor",
    title: "Kalim Backdoor Malware Analysis Report",
    date: "2025-12-12",
    tag: ["APT", "MALWARE"],
    severity: "CRITICAL",
    readTime: "18 MIN READ",
    excerpt: "64-bit DLL backdoor attributed to MuddyWater. Establishes persistence via COM-based startup shortcut, then performs host fingerprinting, encrypted C2 comms with moodleuni[.]com, remote shell execution, and HTTPS data exfiltration.",
    iocs: [
      { type: "SHA256", indicator: "0c8071494bc155c96f2cee998200f63efffcb5a064c021de0925504271806229", family: "Kalim", confidence: "HIGH" },
      { type: "DOMAIN", indicator: "moodleuni[.]com", family: "C2 Kalim", confidence: "HIGH" },
      { type: "IP", indicator: "150.171.27.12", family: "C2 Kalim", confidence: "MEDIUM" },
    ],
    yara: [
      {
        name: "kalim",
        description: "Detects Kalim malware",
        author: "SalahEldin Fikri",
        rule: "rule kalim\n{\n    meta:\n        description = \"Detects Kalim malware\"\n        author      = \"SalahEldin Fikri\"\n    strings:\n        $m1  = \"kalim.pdb\" wide ascii\n        $s1  = \"UPLOAD\"\n        $s2  = \"isHidden\"\n        $s3  = \"/command\"\n        $s4  = \"sleepTime\"\n        $s5  = \"hardwareId\"\n        $s6  = \"pending\"\n        $s7  = \"ctrlc\"\n        $s8  = \"terminate\"\n        $s9  = { 8D 01 02 04 08 10 20 40 80 1B 36 }\n        $s10 = \"KifHsNH6Xhgyebsr\"\n    condition:\n        uint16(0) == 0x5A4D and\n        filesize < 500KB and\n        ($m1) and\n        7 of ($s*)\n}",
      },
    ],
  },

];
