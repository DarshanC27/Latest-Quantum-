"""SPDX licence metadata and third-party component signatures.

The licence question a company actually needs answered is not "which
licences appear" but "which obligations have we taken on without noticing".
So each entry records the obligation in plain English and the situation in
which it bites, rather than a bare identifier.
"""

from __future__ import annotations

from typing import Dict, NamedTuple, Optional, Tuple


class Licence(NamedTuple):
    spdx: str
    name: str
    category: str  # permissive | weak-copyleft | strong-copyleft | proprietary | unknown
    obligation: str
    commercial_risk: str  # severity-style rating for a commercial product
    note: str


LICENCES: Dict[str, Licence] = {
    "MIT": Licence(
        "MIT", "MIT License", "permissive",
        "Keep the copyright notice and licence text in your distribution.",
        "low",
        "No source disclosure. Safe for commercial and SaaS use.",
    ),
    "ISC": Licence(
        "ISC", "ISC License", "permissive",
        "Keep the copyright notice.",
        "low",
        "Functionally equivalent to MIT.",
    ),
    "BSD-2-Clause": Licence(
        "BSD-2-Clause", "BSD 2-Clause", "permissive",
        "Keep the copyright notice and disclaimer.",
        "low",
        "No source disclosure.",
    ),
    "BSD-3-Clause": Licence(
        "BSD-3-Clause", "BSD 3-Clause", "permissive",
        "Keep the notice, and do not use contributor names to endorse your product.",
        "low",
        "No source disclosure.",
    ),
    "Apache-2.0": Licence(
        "Apache-2.0", "Apache License 2.0", "permissive",
        "Keep the NOTICE file, state significant changes, and pass on the "
        "patent grant.",
        "low",
        "Includes an express patent licence, which terminates if you bring "
        "a patent claim against the project.",
    ),
    "0BSD": Licence(
        "0BSD", "Zero-Clause BSD", "permissive",
        "None.", "low", "Public-domain equivalent.",
    ),
    "Unlicense": Licence(
        "Unlicense", "The Unlicense", "permissive",
        "None.", "low", "Public-domain dedication.",
    ),
    "MPL-2.0": Licence(
        "MPL-2.0", "Mozilla Public License 2.0", "weak-copyleft",
        "If you modify a covered file, publish the source of that file.",
        "medium",
        "File-level copyleft. Your own separate files are unaffected, so it "
        "is usually workable in a commercial product.",
    ),
    "LGPL-2.1": Licence(
        "LGPL-2.1", "GNU Lesser GPL 2.1", "weak-copyleft",
        "Link dynamically, and let users replace the library with their own "
        "build.",
        "medium",
        "Static linking pulls your application into the copyleft scope.",
    ),
    "LGPL-3.0": Licence(
        "LGPL-3.0", "GNU Lesser GPL 3.0", "weak-copyleft",
        "As LGPL-2.1, plus the anti-tivoisation installation-information "
        "requirement.",
        "medium",
        "Relevant if you ship the software on hardware you lock down.",
    ),
    "EPL-2.0": Licence(
        "EPL-2.0", "Eclipse Public License 2.0", "weak-copyleft",
        "Publish source for modifications to covered files.",
        "medium",
        "File-level copyleft with a patent grant.",
    ),
    "GPL-2.0": Licence(
        "GPL-2.0", "GNU General Public License 2.0", "strong-copyleft",
        "Anything you distribute that links this code must itself be GPL-2.0, "
        "with source.",
        "high",
        "Distribution triggers it; running it as an internal service does not.",
    ),
    "GPL-3.0": Licence(
        "GPL-3.0", "GNU General Public License 3.0", "strong-copyleft",
        "As GPL-2.0, plus patent and anti-tivoisation terms.",
        "high",
        "Incompatible with GPL-2.0-only code in the same work.",
    ),
    "AGPL-3.0": Licence(
        "AGPL-3.0", "GNU Affero General Public License 3.0", "strong-copyleft",
        "Users interacting with the software over a network must be offered "
        "its complete source, including your modifications.",
        "critical",
        "The network clause is what catches SaaS companies: you do not have "
        "to ship anything for the obligation to trigger. Merely running a "
        "modified AGPL component behind your web service is enough.",
    ),
    "SSPL-1.0": Licence(
        "SSPL-1.0", "Server Side Public License", "proprietary",
        "Offering the software as a service obliges you to release the source "
        "of your entire service stack.",
        "critical",
        "Not recognised as open source by the OSI. Treated by most legal "
        "teams as commercial-use-prohibited without a paid licence.",
    ),
    "BUSL-1.1": Licence(
        "BUSL-1.1", "Business Source License 1.1", "proprietary",
        "Production use is restricted until the change date, then it converts "
        "to an open licence.",
        "high",
        "Commercial production use usually requires a paid licence today.",
    ),
    "Elastic-2.0": Licence(
        "Elastic-2.0", "Elastic License 2.0", "proprietary",
        "You may not provide the software to others as a managed service.",
        "high",
        "Blocks hosted-service resale.",
    ),
    "CC-BY-NC-4.0": Licence(
        "CC-BY-NC-4.0", "Creative Commons BY-NC 4.0", "proprietary",
        "Non-commercial use only, with attribution.",
        "critical",
        "Unusable in a commercial product. Most often turns up in fonts, "
        "icon sets and stock imagery rather than code.",
    ),
    "proprietary": Licence(
        "proprietary", "Proprietary / vendor terms", "proprietary",
        "Comply with the vendor's terms of service; there is no open licence "
        "to fall back on.",
        "medium",
        "Usually a hosted third-party service rather than shipped code. The "
        "exposure is contractual and data-protection related rather than "
        "source disclosure.",
    ),
    "OSL-3.0": Licence(
        "OSL-3.0", "Open Software License 3.0", "strong-copyleft",
        "Derivative works must be released under OSL-3.0, and the network "
        "clause treats external deployment as distribution.",
        "high",
        "Copyleft with a network trigger comparable to AGPL.",
    ),
    "UNKNOWN": Licence(
        "UNKNOWN", "Undetermined", "unknown",
        "Establish the licence before shipping.",
        "medium",
        "An unlicensed dependency is legally worse than a copyleft one: with "
        "no grant at all, the default is that you have no right to use it.",
    ),
}


class Component(NamedTuple):
    name: str
    licence: str
    detect: Tuple[str, ...]  # regexes matched against markup and script URLs
    version_group: bool  # whether the pattern captures a version
    end_of_life: Optional[str] = None  # versions no longer supported
    note: str = ""


# Signatures for components commonly served from a public web front end.
# Version capture uses group 1 where available.
COMPONENTS: Tuple[Component, ...] = (
    # Version-bearing patterns come first: a CDN path may place directories
    # between the version and the filename, so the version must not be
    # anchored to the extension.
    Component("jQuery", "MIT",
              (r"jquery[/@\-](\d+\.\d+(?:\.\d+)?)", r"jquery(?:\.min)?\.js"),
              True, end_of_life="<3.5.0",
              note="Versions before 3.5.0 carry known cross-site scripting flaws."),
    Component("jQuery UI", "MIT", (r"jquery-ui[/@\-](\d+\.\d+(?:\.\d+)?)",), True,
              end_of_life="<1.13.0"),
    Component("Bootstrap", "MIT",
              (r"bootstrap[/@\-](\d+\.\d+(?:\.\d+)?)", r"bootstrap(?:\.min)?\.(?:js|css)"),
              True, end_of_life="<4.0.0",
              note="Bootstrap 3 reached end of life in 2019."),
    Component("AngularJS", "MIT", (r"angular(?:\.min)?\.js", r"angular[/@](\d+\.\d+\.\d+)"),
              True, end_of_life="all",
              note="AngularJS reached end of life in January 2022 and receives "
                   "no security patches."),
    Component("Angular", "MIT", (r"@angular/core@?(\d+\.\d+\.\d+)?",), True),
    Component("React", "MIT", (r"react[/@\-](\d+\.\d+\.\d+)", r"react(?:\.production)?\.min\.js"), True),
    Component("Vue.js", "MIT", (r"vue[/@\-](\d+\.\d+\.\d+)", r"vue(?:\.min)?\.js"), True),
    Component("Svelte", "MIT", (r"svelte[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Ember.js", "MIT", (r"ember[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Backbone.js", "MIT", (r"backbone[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Underscore.js", "MIT", (r"underscore[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Lodash", "MIT", (r"lodash[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Moment.js", "MIT", (r"moment[/@\-](\d+\.\d+\.\d+)",), True,
              note="In maintenance mode; the project recommends migrating away."),
    Component("Axios", "MIT", (r"axios[/@\-](\d+\.\d+\.\d+)",), True),
    Component("D3.js", "ISC", (r"d3[/@\-v]?(\d+\.\d+\.\d+)", r"d3(?:\.min)?\.js"), True),
    Component("Chart.js", "MIT", (r"chart\.?js[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Highcharts", "Elastic-2.0", (r"highcharts",), False,
              note="Free for non-commercial use only; commercial deployment "
                   "requires a purchased licence."),
    Component("FullCalendar", "MIT", (r"fullcalendar[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Font Awesome", "CC-BY-NC-4.0", (r"font-?awesome[/@\-](\d+\.\d+\.\d+)",), True,
              note="Icons are CC BY 4.0 and code is MIT in the free tier; Pro "
                   "icons are proprietary. Confirm which tier is deployed."),
    Component("Tailwind CSS", "MIT", (r"tailwind(?:css)?[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Foundation", "MIT", (r"foundation[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Modernizr", "MIT", (r"modernizr[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Popper.js", "MIT", (r"popper[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Select2", "MIT", (r"select2[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Swiper", "MIT", (r"swiper[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Slick Carousel", "MIT", (r"slick[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Video.js", "Apache-2.0", (r"video\.?js[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Leaflet", "BSD-2-Clause", (r"leaflet[/@\-](\d+\.\d+\.\d+)",), True),
    Component("Three.js", "MIT", (r"three[/@\-r]?(\d+)",), True),
    Component("GSAP", "Elastic-2.0", (r"gsap[/@\-](\d+\.\d+\.\d+)", r"TweenMax"), True,
              note="Standard licence is free only for non-commercial use; "
                   "commercial sites need a Club GreenSock membership."),
    Component("WordPress", "GPL-2.0", (r"wp-content/", r"wp-includes/"), False,
              note="GPL applies to the platform and to themes and plugins "
                   "derived from it."),
    Component("Drupal", "GPL-2.0", (r"/sites/default/files/", r"Drupal\.settings"), False),
    Component("Joomla", "GPL-2.0", (r"/media/jui/", r"joomla"), False),
    Component("Magento", "OSL-3.0", (r"/static/version\d+/frontend/", r"Magento_"), False),
    Component("TYPO3", "GPL-2.0", (r"/typo3conf/", r"/typo3temp/"), False),
    Component("Ghost", "MIT", (r"/ghost/", r"ghost-sdk"), False),
    Component("Shopify", "proprietary", (r"cdn\.shopify\.com",), False),
    Component("Squarespace", "proprietary", (r"squarespace\.com",), False),
    Component("Wix", "proprietary", (r"wixstatic\.com", r"parastorage\.com"), False),
    Component("HubSpot", "proprietary", (r"hs-scripts\.com", r"hubspot"), False),
    Component("Google Analytics", "proprietary",
              (r"google-analytics\.com", r"googletagmanager\.com"), False,
              note="Transfers visitor data to a third party; confirm the UK "
                   "GDPR transfer basis and cookie consent position."),
    Component("Matomo", "GPL-3.0", (r"matomo\.js", r"piwik\.js"), False),
    Component("Sentry", "BUSL-1.1", (r"sentry[/@\-](\d+\.\d+\.\d+)", r"browser\.sentry-cdn\.com"), True),
    Component("Grafana", "AGPL-3.0", (r"grafana",), False,
              note="Grafana relicensed to AGPL-3.0 in 2021. Self-hosting with "
                   "modifications triggers the network source obligation."),
    Component("MongoDB", "SSPL-1.0", (r"mongodb",), False),
    Component("Elasticsearch", "Elastic-2.0", (r"elasticsearch",), False),
)

# Spellings seen in real manifests that map onto a canonical entry.
_LICENCE_ALIASES = {
    "Apache 2.0": "Apache-2.0",
    "Apache-2": "Apache-2.0",
    "BSD": "BSD-3-Clause",
    "GPLv2": "GPL-2.0",
    "GPLv3": "GPL-3.0",
    "AGPLv3": "AGPL-3.0",
    "GPL-2.0-only": "GPL-2.0",
    "GPL-3.0-only": "GPL-3.0",
    "GPL-2.0-or-later": "GPL-2.0",
    "GPL-3.0-or-later": "GPL-3.0",
    "AGPL-3.0-only": "AGPL-3.0",
    "AGPL-3.0-or-later": "AGPL-3.0",
    "LGPL-2.1-only": "LGPL-2.1",
    "LGPL-3.0-only": "LGPL-3.0",
    "commercial": "proprietary",
    "UNLICENSED": "proprietary",
}


def licence_for(identifier: str) -> Licence:
    if not identifier:
        return LICENCES["UNKNOWN"]
    key = _LICENCE_ALIASES.get(identifier, identifier)
    if key in LICENCES:
        return LICENCES[key]
    # Match case-insensitively before giving up, since manifests are not
    # consistent about SPDX capitalisation.
    lowered = key.lower()
    for spdx, licence in LICENCES.items():
        if spdx.lower() == lowered:
            return licence
    return LICENCES["UNKNOWN"]
