# Advisory Source Compliance

This document defines the minimum attribution, caching, refresh, and
redistribution rules Vigil must follow when Phase 16 ingests public
vulnerability and advisory sources.

The goal is conservative and auditable use of third-party data:

- keep every record tied to its original source URL and fetch time
- preserve source-specific identifiers, timestamps, and provenance fields
- avoid implying source endorsement of Vigil
- keep operating from the last trusted local cache when a refresh fails
- avoid redistributing branded assets, logos, or full third-party prose unless
  the source terms clearly allow it

## NVD (NIST)

- Primary interface: prefer the NVD 2.0 APIs. NVD documents the CVE and CPE
  APIs as the preferred way to stay current, while the traditional JSON feeds
  remain a fallback.
- Required attribution: any Vigil surface that uses the live NVD API should
  display the notice required by the NVD Terms of Use: "This product uses the
  NVD API but is not endorsed or certified by the NVD."
- Provenance to preserve: CVE ID, CPE and CPE-match identifiers, source URL,
  `published`, `lastModified`, fetch timestamp, API schema/version metadata,
  and any NVD change-history identifiers once that ingestion lands.
- Refresh cadence: keep automated refreshes conservative. Vigil already uses a
  2-hour minimum interval for live sync, which aligns with the NVD guidance and
  the update frequency of the modified/recent feeds.
- Redistribution rule: keep NVD attribution attached to cached records and do
  not present modified content as if it were original NVD text. If Vigil
  normalizes or truncates NVD material, the record should still identify NVD as
  the upstream source while making it clear the presentation was transformed by
  Vigil.
- Risk note: NVD content is provided "as is" and NIST disclaims warranty, so
  Vigil must keep operator-facing language explicit that advisory matches are a
  decision aid, not proof of compromise.

## EUVD (ENISA)

- Primary interface: use the official EUVD site and any future official
  machine-readable export that ENISA publishes. As of this review, the public
  site is live and publicly accessible, but a stable public API contract was
  not identified in ENISA's public documentation.
- Attribution rule: keep ENISA / EUVD as the named source on every imported
  record and retain the original EUVD record URL when present.
- Redistribution rule: ENISA's legal notice authorizes reproduction of ENISA
  material when the source is acknowledged, unless a page says otherwise.
  Third-party images and materials are excluded from that blanket permission.
- Refresh cadence: do not assume a fixed publication schedule. Poll only
  official EUVD surfaces, respect explicit timestamps, and prefer low-frequency
  scheduled refresh plus manual re-checks until ENISA publishes a clearer feed
  contract.
- Implementation note: because the public EUVD site is currently JavaScript-led,
  any ingestion path should treat parsing and availability as unstable until
  ENISA publishes a formal machine-readable interface or schema.

## JVN / JVN iPedia / MyJVN

- Primary interface: use JVN iPedia public feeds and schemas, not the bundled
  MyJVN client tools.
- Feed timing: JVN documents that the new and updated JVNDBRSS feeds refresh
  twice daily, yearly and detail feeds refresh weekly, and vendor/product lists
  refresh monthly.
- Attribution rule: preserve the JVN or JVN iPedia source URL, JVNDB/JVNDBRSS
  identifier, vendor/product references, and last-updated timestamp for every
  imported record.
- Redistribution rule: keep the public feed data tied to its original source
  and avoid bundling or redistributing the MyJVN tools themselves. The MyJVN
  tools terms expressly forbid copying, distribution, lending, transfer, or
  removal of copyright/trademark notices.
- Cache rule: retain upstream timestamps and checksums so Vigil can show when a
  JVN-derived record is stale or when an upstream yearly/detail feed changed.
- Risk note: JVN content is published "as is" and may change after publication,
  so Vigil should preserve both first-seen and last-seen timestamps where
  possible.

## NCSC (UK)

- Primary interface: use official NCSC reports/advisories pages and the NCSC
  RSS feeds for change discovery.
- Attribution rule: acknowledge NCSC as the source and include a link back to
  the original page when Vigil surfaces a derived advisory.
- Redistribution rule: NCSC website content is generally reusable under the UK
  Open Government Licence v3.0 unless a page says otherwise. Vigil should link
  the source and the OGL when reproducing substantive text. Do not reuse logos
  or third-party images under the OGL.
- Refresh cadence: no strict publication interval is promised. Use RSS for
  discovery and rely on published/reviewed dates and per-article timestamps.
- Implementation note: prefer storing structured metadata and short normalized
  summaries instead of copying long guidance text into the local cache.

## BSI / CERT-Bund

- Primary interface: use official BSI advisory and warning pages plus the BSI
  RSS feeds for CERT-Bund short vulnerability notices and BITS advisories.
- Attribution rule: preserve the original BSI or CERT-Bund URL, publication
  date, advisory title, and any official severity/risk labels carried by the
  source.
- Refresh cadence: BSI exposes RSS feeds for advisory discovery but does not
  publish a single fixed refresh contract for the reviewed public advisory
  pages. Poll conservatively from the RSS feeds and use the source timestamps.
- Redistribution rule: keep redistribution conservative. The public pages
  reviewed during this pass clearly expose advisories and RSS feeds, but they do
  not expose a machine-friendly open-content grant comparable to NCSC's OGL on
  the same pages. Until BSI-specific reuse terms are validated for the exact
  advisory surface, Vigil should limit itself to metadata, short source-linked
  summaries, and operator navigation back to the official page.
- Lifecycle note: BSI documents that some formal warnings are archived after one
  month when a manufacturer has taken suitable action, or after six months when
  no suitable action was taken. Vigil should not treat disappearance or
  archiving as proof that the underlying risk no longer matters.

## Shared implementation rules

- Never strip the upstream source URL, record identifier, or publish/update
  timestamps during normalization.
- Keep a per-source health/status field so operators can see whether a source is
  fresh, stale, or currently unavailable.
- Keep the last trusted cache on refresh failure; do not clear matches just
  because a public source is temporarily unreachable.
- Prefer derived metadata, identifiers, severity, mitigation URLs, and short
  summaries over large verbatim copies of third-party advisory prose.
- Treat logos, screenshots, and non-text media as excluded unless the relevant
  source terms clearly allow reuse.
- Re-check source terms before enabling any bulk export, fleet redistribution,
  or commercial rule-pack publishing that republishes upstream text beyond local
  operator use.

## Sources reviewed

- NVD developers pages: CVE API, CVE Change History API, data feeds, terms of
  use, and legal disclaimer
- ENISA legal notice and the May 13, 2025 EUVD launch announcement
- JVN iPedia feed documentation, feed-status pages, and MyJVN terms of use
- NCSC terms and conditions plus RSS feed documentation
- BSI RSS/advisory pages, CERT-Bund pages, and public legal-notice references
