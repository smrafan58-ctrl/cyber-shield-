import React from 'react';
import {
  ShieldAlert,
  Lock,
  AlertTriangle,
  PhoneCall,
  CheckCircle2,
  ArrowRight,
} from 'lucide-react';

interface SafetyGuideSectionProps {
  onNavigateToScanner: (sampleUrl?: string) => void;
}

export const SafetyGuideSection: React.FC<SafetyGuideSectionProps> = ({
  onNavigateToScanner,
}) => {
  const guideChapters = [
    {
      number: '01',
      title: 'How Phishing URLs Work',
      summary:
        'Phishing links are crafted to trick you into believing you are visiting a trusted website so that you voluntarily enter passwords, PINs, OTPs, or card details.',
      details: [
        'Attackers control the registrable domain (the rightmost core domain before the top-level suffix, such as "example.org" in "google.com.security-check.example.org").',
        'Everything to the left of the registrable domain (subdomains) and everything after the first slash (the file path) can be freely chosen by the owner of that domain.',
        'Always read a hostname from right to left—stop at the first single "/" slash and check the two labels immediately before it.',
      ],
      sampleUrl: 'https://google.com.security-check.example.org/',
    },
    {
      number: '02',
      title: 'How Fake Banking Domains Deceive Users',
      summary:
        'Fraudsters register domains that combine a bank’s name with action words like "-kyc", "-reward", "-update", or "-netbanking" on commercial top-level domains.',
      details: [
        'For example, an attacker might register "sbi-kyc-update.com" or "hdfcbank-verify.net" and send SMS alerts claiming your account or PAN card will be blocked today.',
        'Even if a fake banking site displays a padlock icon (HTTPS), that only means the connection to the attacker’s server is encrypted—it does not verify that the site belongs to your bank.',
        'Never click links inside SMS messages or WhatsApp forwards to complete banking KYC or redeem reward points.',
      ],
      sampleUrl: 'https://sbi-kyc-update.example.com/login',
    },
    {
      number: '03',
      title: 'How Typosquatting & Lookalike Domains Work',
      summary:
        'Typosquatting exploits visual similarity and typing mistakes by replacing letters with lookalike characters (homoglyphs) or omitting a single letter.',
      details: [
        'Common visual substitutions include replacing lowercase "l" with the number "1" (e.g., "paypa1.com"), replacing "o" with zero "0" ("g00gle.com"), or replacing "m" with "rn" ("arnazon.com").',
        'Internationalized Domain Names (IDNs) encoded with Punycode ("xn--") can also substitute Latin characters with visually identical Cyrillic or Greek letters.',
        'Inspect domains in a monospace font or use a deterministic URL parser when a link looks slightly off.',
      ],
      sampleUrl: 'https://paypa1-example.com/login',
    },
    {
      number: '04',
      title: 'How Malicious Redirects & Shorteners Hide Destinations',
      summary:
        'Attackers use URL shorteners or open-redirect query parameters to conceal where a link actually leads.',
      details: [
        'Shortened links (such as bit.ly or tinyurl.com) obscure the final domain until your browser follows the redirect.',
        'Query parameters like "?redirect=https://..." or "?next=https://..." can abuse redirect endpoints on third-party sites to forward you to a credential-harvesting page.',
        'Additionally, placing an "@" symbol in a URL authority (e.g., "https://trusted-bank.com@malicious-host.org") causes browsers to ignore the text before "@" and connect to the host after it.',
      ],
      sampleUrl: 'https://example.com/login?redirect=https://untrusted-destination.xyz',
    },
    {
      number: '05',
      title: 'How to Identify Suspicious Login Pages',
      summary:
        'A login form is only as trustworthy as the registrable domain hosting it—never judge a login page by its logos, colors, or padlock icon.',
      details: [
        'Phishing kits copy the exact HTML, CSS, and brand logos of popular email, cloud, and banking login screens.',
        'Check whether the domain is a raw IP address (like "http://192.0.2.15/login"), uses a non-standard port, or chains multiple hyphens.',
        'Use a password manager: password managers match credentials strictly against the registrable domain and will refuse to auto-fill your password on a lookalike phishing domain.',
      ],
    },
    {
      number: '06',
      title: 'How to Verify Official Government & Banking Websites',
      summary:
        'Official institutions operate on strictly controlled, verifiable domain registries.',
      details: [
        'In India, official central and state government portals use ".gov.in" or ".nic.in" (for example, "incometax.gov.in", "parivahan.gov.in", "cybercrime.gov.in").',
        'Recognized Indian banks use their verified corporate domains or the ".bank" / ".sbi" registry—never generic ".xyz", ".top", ".click", or multi-hyphenated domains for account verification.',
        'When in doubt, close the link, open a fresh browser tab, and navigate to your bank or government portal using a known bookmark.',
      ],
    },
    {
      number: '07',
      title: 'How Digital Arrest Scams Use Fear and Urgency',
      summary:
        'In "Digital Arrest" scams, criminals impersonate police, CBI, Customs, Enforcement Directorate (ED), or telecom officials to extort money under false legal threats.',
      details: [
        'Victims receive a call or link claiming their Aadhaar, PAN, or phone number was linked to an illegal parcel, money laundering, or arrest warrant.',
        'Scammers send links to fake court orders, fake FIR copies, or fake verification portals on private domains (e.g., "cbi-notice-verify.com") and demand the victim stay on a continuous video call ("digital arrest") while transferring funds for "verification".',
        'Indian law enforcement and courts NEVER conduct "digital arrests" over video calls, never send arrest warrants via messaging links, and never ask citizens to transfer money to "clear" their name.',
      ],
      sampleUrl: 'https://cbi-notice-digital-arrest.example.org/verify',
    },
    {
      number: '08',
      title: 'Why Authority Claims in a Link Must Never Be Trusted Alone',
      summary:
        'Anyone can register a domain containing words like "police", "supreme-court", "customs", "tax", or "bank-security" in minutes.',
      details: [
        'Conversely, a URL scanner cannot reliably identify every digital arrest scam or fraud campaign, because scammers may also host decoy pages on newly registered clean-looking domains or conduct the scam primarily over voice/video calls.',
        'Treat awareness guidelines and URL heuristics as educational first-line checks, not a substitute for formal security investigation or independent verification.',
      ],
    },
  ];

  return (
    <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8 space-y-10">
      {/* Page Header */}
      <div className="border-b border-slate-800 pb-6">
        <p className="text-xs font-medium text-sky-400 mb-2">
          Cybersecurity Awareness & Practical Defense
        </p>
        <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold tracking-tight text-white">
          URL Threat Identification & Safety Guide
        </h1>
        <p className="mt-2 text-sm sm:text-base text-slate-300 max-w-3xl leading-relaxed">
          Learn how attackers structure deceptive links, how to read domain hierarchies accurately, and what to do if you encounter phishing, banking fraud, or digital arrest scams.
        </p>
      </div>

      {/* URL Anatomy Visual Diagram */}
      <section
        aria-labelledby="url-anatomy-heading"
        className="rounded-xl border border-slate-800 bg-[#111827] p-6"
      >
        <h2
          id="url-anatomy-heading"
          className="text-base font-semibold text-slate-100 mb-2"
        >
          How to Read a Deceptive URL Before You Click
        </h2>
        <p className="text-xs sm:text-sm text-slate-400 mb-5">
          Attackers place familiar brand names at the beginning of a link so your eye stops reading before reaching the real domain owner.
        </p>

        <div className="pt-4 border-t border-slate-800">
          <div className="font-mono text-sm sm:text-base flex flex-wrap items-center gap-y-2 pb-5 border-b border-slate-800">
            <span className="text-slate-400">https://</span>
            <span className="text-amber-300 underline decoration-amber-500/60 decoration-2 underline-offset-4">
              google.com.security-check.
            </span>
            <span className="text-rose-400 font-bold underline decoration-rose-500 decoration-2 underline-offset-4 mx-1">
              example.org
            </span>
            <span className="text-slate-400">/account/login</span>
          </div>

          <div className="mt-5 grid grid-cols-1 sm:grid-cols-3 gap-6 sm:divide-x sm:divide-slate-800 text-xs">
            <div className="sm:pr-4">
              <div className="font-mono font-semibold text-amber-300">
                1. Subdomain (Attacker-Controlled)
              </div>
              <p className="mt-1.5 text-slate-400 leading-relaxed">
                <code className="text-slate-200">google.com.security-check</code> is merely a prefix created by the owner of <code className="text-slate-200">example.org</code>. It has no connection to Google.
              </p>
            </div>

            <div className="sm:px-4">
              <div className="font-mono font-semibold text-rose-300">
                2. Registrable Domain (True Destination)
              </div>
              <p className="mt-1.5 text-slate-300 leading-relaxed">
                <code className="text-white font-semibold">example.org</code> is the actual server your browser connects to. Always inspect the registrable domain immediately before the first <code className="text-white">/</code>.
              </p>
            </div>

            <div className="sm:pl-4">
              <div className="font-mono font-semibold text-slate-200">
                3. Path & Route
              </div>
              <p className="mt-1.5 text-slate-400 leading-relaxed">
                <code className="text-slate-200">/account/login</code> indicates a sign-in page. Combined with an unrelated domain, this signals credential harvesting.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* 8 Educational Chapters Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {guideChapters.map((chapter) => (
          <article
            key={chapter.number}
            className="rounded-xl border border-slate-800 bg-[#111827] p-6 flex flex-col justify-between"
          >
            <div>
              <div className="flex items-baseline gap-2.5">
                <span className="font-mono text-xs font-semibold text-sky-400 tabular-nums">
                  {chapter.number}.
                </span>
                <h2 className="text-base sm:text-lg font-semibold text-slate-100">
                  {chapter.title}
                </h2>
              </div>

              <p className="mt-2.5 text-sm text-slate-200 leading-relaxed">
                {chapter.summary}
              </p>

              <ul className="mt-4 space-y-2 text-xs sm:text-sm text-slate-400">
                {chapter.details.map((point) => (
                  <li key={point} className="flex items-start gap-2">
                    <CheckCircle2
                      className="h-4 w-4 text-sky-400 shrink-0 mt-0.5"
                      aria-hidden="true"
                    />
                    <span className="leading-relaxed">{point}</span>
                  </li>
                ))}
              </ul>
            </div>

            {chapter.sampleUrl && (
              <div className="mt-5 pt-4 border-t border-slate-800/80 flex items-center justify-between gap-3">
                <code className="text-xs font-mono text-slate-400 truncate">
                  Example: {chapter.sampleUrl}
                </code>
                <button
                  type="button"
                  onClick={() => onNavigateToScanner(chapter.sampleUrl)}
                  className="inline-flex items-center gap-1.5 text-xs font-semibold text-sky-400 hover:text-sky-300 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <span>Test in Scanner</span>
                  <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            )}
          </article>
        ))}
      </div>

      {/* Chapter 09: How to Report Suspicious Links & Cybercrime in India */}
      <section
        aria-labelledby="report-india-heading"
        className="rounded-xl border border-sky-500/30 bg-[#111827] p-6 sm:p-8"
      >
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6">
          <div className="max-w-3xl">
            <div className="flex items-center gap-2.5 text-sky-400 text-xs font-semibold mb-2">
              <PhoneCall className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>09. Official Incident Reporting in India</span>
            </div>
            <h2
              id="report-india-heading"
              className="text-xl sm:text-2xl font-bold text-white"
            >
              How to Report Suspicious Links, Phishing & Cyber Fraud in India
            </h2>
            <p className="mt-2 text-sm text-slate-300 leading-relaxed">
              If you have received a deceptive link, encountered a digital arrest scam call, or suffered unauthorized financial loss, use these official Government of India channels immediately:
            </p>

            <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs sm:text-sm">
              <div className="rounded-lg border border-slate-800 bg-[#0B1120] p-4">
                <div className="font-semibold text-slate-100">
                  1. National Cyber Crime Helpline: <span className="font-mono text-sky-400">1930</span>
                </div>
                <p className="mt-1.5 text-slate-400 leading-relaxed">
                  Dial <strong className="text-slate-200 font-mono">1930</strong> immediately if you have lost money to a banking, UPI, or digital arrest scam so the Citizen Financial Cyber Fraud Reporting system can work to freeze fraudulent transfers.
                </p>
              </div>

              <div className="rounded-lg border border-slate-800 bg-[#0B1120] p-4">
                <div className="font-semibold text-slate-100">
                  2. National Cyber Crime Portal (<span className="font-mono text-sky-400">cybercrime.gov.in</span>)
                </div>
                <p className="mt-1.5 text-slate-400 leading-relaxed">
                  File formal complaints regarding phishing links, impersonation scams, online extortion, or cybercrime through the Ministry of Home Affairs portal at <code className="text-slate-200">https://cybercrime.gov.in</code>.
                </p>
              </div>

              <div className="rounded-lg border border-slate-800 bg-[#0B1120] p-4">
                <div className="font-semibold text-slate-100">
                  3. Chakshu on Sanchar Saathi (<span className="font-mono text-sky-400">sancharsaathi.gov.in</span>)
                </div>
                <p className="mt-1.5 text-slate-400 leading-relaxed">
                  Report suspected fraud communications received via SMS, phone call, or WhatsApp (such as fake KYC warnings, electricity disconnection threats, or digital arrest calls) even if you have not lost money.
                </p>
              </div>

              <div className="rounded-lg border border-slate-800 bg-[#0B1120] p-4">
                <div className="font-semibold text-slate-100">
                  4. CERT-In Incident Reporting (<span className="font-mono text-sky-400">incident@cert-in.org.in</span>)
                </div>
                <p className="mt-1.5 text-slate-400 leading-relaxed">
                  Computer security incidents, phishing infrastructure targeting Indian organizations, and technical vulnerabilities can be reported to the Indian Computer Emergency Response Team.
                </p>
              </div>
            </div>
          </div>

          <div className="lg:w-80 shrink-0 rounded-lg border border-amber-500/30 bg-amber-950/15 p-5 text-xs text-slate-300 space-y-3">
            <div className="flex items-center gap-2 font-semibold text-amber-300 text-sm">
              <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>Important Scope Note</span>
            </div>
            <p className="leading-relaxed">
              This guide provides educational cybersecurity awareness, not a formal forensic investigation or legal advice.
            </p>
            <p className="leading-relaxed">
              No automated URL scanner can detect every scam—especially when attackers use newly registered domains without suspicious keywords or conduct fraud over phone and video calls.
            </p>
            <div className="pt-2 border-t border-amber-500/20 flex items-center gap-2 text-slate-400">
              <Lock className="h-3.5 w-3.5 text-sky-400 shrink-0" aria-hidden="true" />
              <span>Always verify independently.</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};
