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


  //{
  //  slug: "vulcan-malware",
  //  title: "Vulcan Malware: Analysis of a Multi-Persistent Go-Based Linux Implant",
  //  date: "2026-08-13",
  //  tag: "MALWARE",
  //  severity: "CRITICAL",
  //  readTime: "12 MIN READ",
  //  excerpt: "A multi-architecture Go-based Linux implant distributed as UPX-packed ELF binaries. Vulcan establishes multiple persistence mechanisms, uses AES-GCM encrypted C2 communication, performs wide-scope network scanning, and targets SSH, Redis, Docker, ADB, Telnet, HTTP, HTTPS, and Huawei-related services.",
  //  iocs: [
  //    {
  //      type: "IPv4",
  //      indicator: "146.19.213.198",
  //      family: "Vulcan",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PORT",
  //      indicator: "8443",
  //      family: "Vulcan C2",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "C2",
  //      indicator: "146.19.213.198:8443",
  //      family: "Vulcan",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "DOMAIN",
  //      indicator: "vulcan-c2.local",
  //      family: "Vulcan",
  //      confidence: "MEDIUM"
  //    },
  //    {
  //      type: "FILE",
  //      indicator: "vulcan-agent",
  //      family: "Vulcan",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PATH",
  //      indicator: "~/.cache/.icons/vulcan-agent",
  //      family: "Vulcan",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PATH",
  //      indicator: "~/.bashrc",
  //      family: "Vulcan Persistence",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PATH",
  //      indicator: "~/.profile",
  //      family: "Vulcan Persistence",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PATH",
  //      indicator: "/etc/init.d/",
  //      family: "Vulcan Persistence",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PATH",
  //      indicator: "/etc/rc.local",
  //      family: "Vulcan Persistence",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PATH",
  //      indicator: "/usr/sbin/ntpdbad",
  //      family: "Vulcan Binary Hijacking",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PATH",
  //      indicator: "/usr/bin/sshd",
  //      family: "Vulcan Binary Hijacking",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PATH",
  //      indicator: "/sbin/agetty",
  //      family: "Vulcan Binary Hijacking",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PORT",
  //      indicator: "22",
  //      family: "Vulcan Network Scanner",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PORT",
  //      indicator: "23",
  //      family: "Vulcan Network Scanner",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PORT",
  //      indicator: "2323",
  //      family: "Vulcan Network Scanner",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PORT",
  //      indicator: "2375",
  //      family: "Vulcan Network Scanner",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PORT",
  //      indicator: "5555",
  //      family: "Vulcan Network Scanner",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PORT",
  //      indicator: "6379",
  //      family: "Vulcan Network Scanner",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PORT",
  //      indicator: "80",
  //      family: "Vulcan Network Scanner",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PORT",
  //      indicator: "443",
  //      family: "Vulcan Network Scanner",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PORT",
  //      indicator: "8080",
  //      family: "Vulcan Network Scanner",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "PORT",
  //      indicator: "37215",
  //      family: "Vulcan Network Scanner",
  //      confidence: "HIGH"
  //    },
  //    {
  //      type: "KEY",
  //      indicator: "can-lab-pre-shared-key-32bytes!!",
  //      family: "Vulcan",
  //      confidence: "HIGH"
  //    }
  //  ],
  //  yara: [
  //    {
  //      name: "Family_Vulcan",
  //      description: "Detects the Vulcan malware family using embedded debug and behavioral strings",
  //      author: "SalahEldin Kamil (Mr_MaTriX)",
  //      rule: "rule Family_Vulcan\n{\n    meta:\n        description = \"Detects Family Vulcan Malware\"\n        author      = \"SalahEldin Kamil (Mr_MaTriX)\"\n    strings:\n        $m1  = \"DEBUG_HTTP2_GOROUTINES\" ascii wide\n        $m2  = \"[DEBUG] Dial error: %v\\n\" ascii wide\n        $m3  = \"[DEBUG] Read error: %v\\n\" ascii wide\n        $m4  = \"[DEBUG] readLoop started\" ascii wide\n        $m5  = \"[DEBUG] Write error: %v\\n\" ascii wide\n        $m6  = \"[DEBUG] Scanning enabled\" ascii wide\n        $m7  = \"[DEBUG] Invalid URL: %v\\n\" ascii wide\n        $m8  = \"GODEBUG sys/cpu: value \\\"\" ascii wide\n        $m9  = \"[DEBUG] Worker %d EXITED\\n\" ascii wide\n        $m10 = \"[DEBUG] Scanning disabled\" ascii wide\n        $m11 = \"GODEBUG: can not enable \\\"\" ascii wide\n        $m12 = \"[DEBUG] Implant starting...insufficient security level\" ascii wide\n        $m13 = \"[DEBUG] WebSocket connected!\" ascii wide\n        $m14 = \"[DEBUG] Worker %d PANIC: %v\\n\" ascii wide\n        $m15 = \"[DEBUG] Unknown command: %s\\n\" ascii wide\n        $m16 = \"[DEBUG] SSH spreader started\" ascii wide\n        $m17 = \"[DEBUG] Worker 0 scanning %s\\n\" ascii wide\n        $m18 = \"[DEBUG] Received task: %s %s\\n\" ascii wide\n        $m19 = \"[DEBUG] SCP to %s failed: %v\\n\" ascii wide\n        $m20 = \"[DEBUG] Unknown DDoS type: %s\\n\" ascii wide\n        $m21 = \"GODEBUG: unknown cpu feature \\\"\" ascii wide\n        $m22 = \"[DEBUG] sendMessageSync failed!\" ascii wide\n        $m23 = \"[DEBUG] Scan worker %d started\\n\" ascii wide\n        $m24 = \"[DEBUG] Usage: <type> <args...>\" ascii wide\n        $m25 = \"[DEBUG] Self-destruct initiatedbad certificate status responseencrypted client hello required\" ascii wide\n        $m26 = \"[DEBUG] SSH spread success to %s\\n\" ascii wide\n        $m27 = \"[DEBUG] SYN flood init error: %v\\n\" ascii wide\n        $m28 = \"[DEBUG] connect() goroutine started\" ascii wide\n        $m29 = \"[DEBUG] sendMessageSync: conn is nil\" ascii wide\n        $m30 = \"[DEBUG] %s exploit SUCCESS on %s:%d\\n\" ascii wide\n        $m31 = \"GODEBUG: no value specified for \\\"\" ascii wide\n        $m32 = \"GODEBUG sys/cpu: can not enable \\\"\" ascii wide\n        $m33 = \"GODEBUG sys/cpu: can not disable \\\"\" ascii wide\n    condition:\n        uint32(0) == 0x464c457f and\n        (any of them)\n}"
  //    },
  //    {
  //      name: "Vulcan_x86",
  //      description: "Detects the Vulcan x86 ELF build using the hardcoded C2 configuration pattern",
  //      author: "SalahEldin Kamil (Mr_MaTriX)",
  //      rule: "rule Vulcan_x86\n{\n    meta:\n        description = \"Detects Vulcan Malware — x86 ELF build\"\n        author      = \"SalahEldin Kamil (Mr_MaTriX)\"\n    strings:\n        $Config = {\n            8D 05 ?? ?? ?? ??\n            89 04 24\n            C7 44 24 04 13 00 00 00\n            8B 44 24 34\n            89 44 24 08\n            E8 ?? ?? ?? ??\n        }\n    condition:\n        any of them\n}"
  //    },
  //    {
  //      name: "Vulcan_AMD64",
  //      description: "Detects the Vulcan AMD64 ELF build using the hardcoded C2 configuration pattern",
  //      author: "SalahEldin Kamil (Mr_MaTriX)",
  //      rule: "rule Vulcan_AMD64\n{\n    meta:\n        description = \"Detects Vulcan Malware — AMD64 ELF build\"\n        author      = \"SalahEldin Kamil (Mr_MaTriX)\"\n    strings:\n        $Config = {\n            48 8D 05 ?? ?? ?? ??\n            BB 13 00 00 00\n            48 8B 4C 24 58\n            E8 ?? ?? ?? ??\n        }\n    condition:\n        any of them\n}"
  //    },
  //    {
  //      name: "Vulcan_ARM5",
  //      description: "Detects the Vulcan ARM5 ELF build",
  //      author: "SalahEldin Kamil (Mr_MaTriX)",
  //      rule: "rule Vulcan_ARM5\n{\n    meta:\n        description = \"Detects Vulcan Malware — ARM5 ELF build\"\n        author      = \"SalahEldin Kamil (Mr_MaTriX)\"\n    strings:\n        $Config = {\n            48 02 ?? ??\n            04 00 8D E5\n            13 00 A0 E3\n            08 00 8D E5\n            38 00 9D E5\n            0C 00 8D E5\n            3D ?? ?? ??\n        }\n    condition:\n        any of them\n}"
  //    },
  //    {
  //      name: "Vulcan_ARM7",
  //      description: "Detects the Vulcan ARM7 ELF build",
  //      author: "SalahEldin Kamil (Mr_MaTriX)",
  //      rule: "rule Vulcan_ARM7\n{\n    meta:\n        description = \"Detects Vulcan Malware — ARM7 ELF build\"\n        author      = \"SalahEldin Kamil (Mr_MaTriX)\"\n    strings:\n        $Config = {\n            44 02 ?? ??\n            04 00 8D E5\n            13 00 A0 E3\n            08 00 8D E5\n            38 00 9D E5\n            0C 00 8D E5\n            59 ?? ?? ??\n        }\n    condition:\n        any of them\n}"
  //    },
  //    {
  //      name: "Vulcan_MIPS",
  //      description: "Detects the Vulcan MIPS big-endian ELF build",
  //      author: "SalahEldin Kamil (Mr_MaTriX)",
  //      rule: "rule Vulcan_MIPS\n{\n    meta:\n        description = \"Detects Vulcan Malware — MIPS big-endian ELF build\"\n        author      = \"SalahEldin Kamil (Mr_MaTriX)\"\n    strings:\n        $Config = {\n            3C 01 00 51 24 21 ?? ??\n            AF A1 00 04\n            24 01 00 13\n            AF A1 00 08\n            8F A1 00 40\n            AF A1 00 0C\n            0C ?? ?? ??\n        }\n    condition:\n        any of them\n}"
  //    },
  //    {
  //      name: "Vulcan_MIPSLE",
  //      description: "Detects the Vulcan MIPS little-endian ELF build",
  //      author: "SalahEldin Kamil (Mr_MaTriX)",
  //      rule: "rule Vulcan_MIPSLE\n{\n    meta:\n        description = \"Detects Vulcan Malware — MIPS little-endian ELF build\"\n        author      = \"SalahEldin Kamil (Mr_MaTriX)\"\n    strings:\n        $Config = {\n            51 00 01 3C ?? ?? 21 24\n            04 00 A1 AF\n            13 00 01 24\n            08 00 A1 AF\n            3C 00 A1 8F\n            0C 00 A1 AF\n            ?? ?? ?? 0C\n        }\n    condition:\n        any of them\n}"
  //    }
  //  ],
  //},

  {
    slug: "lazarusthreatactorprofile",
    title: "Lazarus Group: Threat Actor Profile & 3CX Supply Chain Attack - Complete Technical Analysis",
    date: "2026-07-02",
    tag: "APT",
    severity: "CRITICAL",
    readTime: "40 MIN READ",
    excerpt: "A comprehensive research series covering the Lazarus Group, one of the world's most active nation-state threat actors. The collection includes an in-depth threat actor profile, campaign analyses, reverse engineering reports, malware analysis, indicators of compromise (IOCs), MITRE ATT&CK mappings, and technical investigations into operations attributed to Lazarus. Each report examines different aspects of the group's evolving tactics, techniques, procedures (TTPs), and operational infrastructure.",
    iocs: [
      { type: "SHA256", indicator: "DDE03348075512796241389DFEA5560C20A3D2A2EAC95C894E7BBED5E85A0ACC", family: "3CXDesktopApp.exe", confidence: "HIGH" },
      { type: "SHA256", indicator: "7290A9AEFBB759C9B40EF8A197CF20FD098FD74DD413C4D9D81E77A31E643F49", family: "Trojanized ffmpeg.dll", confidence: "HIGH" },
      { type: "SHA256", indicator: "11BE1803E2E307B647A8A7E02D128335C448FF741BF06BF52B332E0BBF423B03", family: "Trojanized d3dcompiler_47.dll", confidence: "HIGH" },
      { type: "SHA256", indicator: "8AB3A5EAAF8C296080FADF56B265194681D7DA5DA7C02562953A4CB60E147423", family: "VEILEDSIGNAL", confidence: "HIGH" },

      { type: "MD5", indicator: "00A43D64F9B5187A1E1F922B99B09B77", family: "X_TRADER", confidence: "HIGH" },

      { type: "Directory", indicator: "C:\\ProgramData\\TPM\\", family: "X_TRADER", confidence: "MEDIUM" },
      { type: "File", indicator: "C:\\ProgramData\\TPM\\TpmVscMgrSvr.exe", family: "X_TRADER", confidence: "MEDIUM" },
      { type: "File", indicator: "C:\\ProgramData\\TPM\\devobj.dll", family: "X_TRADER", confidence: "MEDIUM" },
      { type: "File", indicator: "X_TRADER-ja.mst", family: "X_TRADER", confidence: "MEDIUM" },
      { type: "File", indicator: "%AppData%\\3CXDesktopApp\\config.json", family: "VEILEDSIGNAL", confidence: "MEDIUM" },

      { type: "Scheduled Task", indicator: "Tpm-VscMgr", family: "Persistence", confidence: "MEDIUM" },
      { type: "Event", indicator: "AVMonitorRefreshEvent", family: "Trojanized ffmpeg.dll", confidence: "MEDIUM" },

      { type: "RC4 Key", indicator: "3jB(2bsG#@c7", family: "Trojanized ffmpeg.dll", confidence: "MEDIUM" },
      { type: "XOR Key", indicator: "0x0DA39F274", family: "X_TRADER", confidence: "MEDIUM" },

      { type: "GitHub", indicator: "https://raw[.]githubusercontent[.]com/IconStorages/images/main/", family: "Dead Drop Resolver", confidence: "HIGH" },

      { type: "Domain", indicator: "msstorageazure[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
      { type: "Domain", indicator: "officestoragebox[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
      { type: "Domain", indicator: "visualstudiofactory[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
      { type: "Domain", indicator: "azuredeploystore[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
      { type: "Domain", indicator: "msstorageboxes[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
      { type: "Domain", indicator: "officeaddons[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
      { type: "Domain", indicator: "sourceslabs[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
      { type: "Domain", indicator: "zacharryblogs[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
      { type: "Domain", indicator: "pbxcloudeservices[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
      { type: "Domain", indicator: "akamaitechcloudservices[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
      { type: "Domain", indicator: "azureonlinestorage[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
      { type: "Domain", indicator: "msedgepackageinfo[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
      { type: "Domain", indicator: "glcloudservice[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
      { type: "Domain", indicator: "pbxsources[.]com", family: "Dead Drop Resolver", confidence: "MEDIUM" },
    ],
    yara: false,
  },

  {
    slug: "lazarus3cxsupplychainfullreport",
    title: "Lazarus 3cxSupplyChain Full Report",
    date: "2026-07-01",
    tag: "Malware Supply Chain Attack",
    severity: "CRITICAL",
    readTime: "14 MIN READ",
    excerpt: "Analysis of the 3CX supply chain attack attributed to the Lazarus Group. The report details the trojanized 3CXDesktopApp.exe, its multi-stage payloads, and the C2 infrastructure used for data exfiltration and remote control.",
    iocs: null,
    yara: null,
  },

  {
    slug: "lazarusthreatactorprofile",
    title: "Lazarus APT Group: Threat Actor Profile",
    date: "2026-07-01",
    tag: "Malware Supply Chain Attack",
    severity: "CRITICAL",
    readTime: "14 MIN READ",
    excerpt: "Lazarus APT Group: Threat Actor Profile. This report provides an in-depth analysis of the Lazarus Group, including their tactics, techniques, and procedures (TTPs), as well as their operational infrastructure and notable campaigns.",
    iocs: null,
    yara: null,
  },

  {
    slug: "lazarussummary",
    title: "Executive Summary: Lazarus APT Group",
    date: "2026-07-01",
    tag: "Malware Supply Chain Attack",
    severity: "CRITICAL",
    readTime: "5 MIN READ",
    excerpt: "Executive summary of the Lazarus APT Group's activities, including their tactics, techniques, and procedures (TTPs), as well as their operational infrastructure and notable campaigns.",
    iocs: null,
    yara: null,
  },

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
