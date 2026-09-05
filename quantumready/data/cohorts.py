"""Seed cohorts for benchmark studies.

These are starting points, not authoritative registers. Every list here
is short and hand-checked rather than long and guessed at, because a
wrong domain in a published study is worse than a missing one -- it
attributes someone else's security posture to an organisation that had
nothing to do with it.

For a full run, supply your own CSV via ``--targets``. Authoritative
sources:

  UK local authorities  https://www.gov.uk/government/organisations
                        https://get-information-schools.service.gov.uk
  UK public sector DNS  https://github.com/alphagov/domains-data
  NHS organisations     https://www.nhs.uk/servicedirectories/
  UK universities       https://www.universitiesuk.ac.uk/universities
  Listed companies      London Stock Exchange constituent lists

Load one with:

    quantumready study --targets councils.csv --cohort "UK councils"

CSV columns: ``name,domain`` and optionally ``sector,region``.
"""

from __future__ import annotations

from typing import Dict, List, NamedTuple


class Subject(NamedTuple):
    name: str
    domain: str
    sector: str = "general"
    region: str = ""


# --- UK local government ---------------------------------------------------
# Sector default of 20 years: councils hold planning records, social care
# files and electoral data for decades.

UK_COUNCILS: List[Subject] = [
    Subject("Surrey County Council", "surreycc.gov.uk", "government", "South East"),
    Subject("Guildford Borough Council", "guildford.gov.uk", "government", "South East"),
    Subject("Woking Borough Council", "woking.gov.uk", "government", "South East"),
    Subject("Birmingham City Council", "birmingham.gov.uk", "government", "West Midlands"),
    Subject("Manchester City Council", "manchester.gov.uk", "government", "North West"),
    Subject("Leeds City Council", "leeds.gov.uk", "government", "Yorkshire"),
    Subject("Bristol City Council", "bristol.gov.uk", "government", "South West"),
    Subject("Sheffield City Council", "sheffield.gov.uk", "government", "Yorkshire"),
    Subject("Nottingham City Council", "nottinghamcity.gov.uk", "government", "East Midlands"),
    Subject("Kent County Council", "kent.gov.uk", "government", "South East"),
    Subject("Hampshire County Council", "hants.gov.uk", "government", "South East"),
    Subject("Essex County Council", "essex.gov.uk", "government", "East"),
    Subject("Cornwall Council", "cornwall.gov.uk", "government", "South West"),
    Subject("Devon County Council", "devon.gov.uk", "government", "South West"),
    Subject("Camden Council", "camden.gov.uk", "government", "London"),
    Subject("Westminster City Council", "westminster.gov.uk", "government", "London"),
]

# --- UK universities -------------------------------------------------------

UK_UNIVERSITIES: List[Subject] = [
    Subject("University of Surrey", "surrey.ac.uk", "education", "South East"),
    Subject("University of Oxford", "ox.ac.uk", "education", "South East"),
    Subject("University of Cambridge", "cam.ac.uk", "education", "East"),
    Subject("Imperial College London", "imperial.ac.uk", "education", "London"),
    Subject("University College London", "ucl.ac.uk", "education", "London"),
    Subject("University of Edinburgh", "ed.ac.uk", "education", "Scotland"),
    Subject("University of Manchester", "manchester.ac.uk", "education", "North West"),
    Subject("University of Bristol", "bristol.ac.uk", "education", "South West"),
    Subject("University of Warwick", "warwick.ac.uk", "education", "West Midlands"),
    Subject("University of Southampton", "soton.ac.uk", "education", "South East"),
    Subject("King's College London", "kcl.ac.uk", "education", "London"),
    Subject("University of Bath", "bath.ac.uk", "education", "South West"),
]

# --- UK listed companies ---------------------------------------------------

UK_LISTED: List[Subject] = [
    Subject("Barclays", "barclays.co.uk", "finance", "London"),
    Subject("Lloyds Banking Group", "lloydsbank.com", "finance", "London"),
    Subject("NatWest Group", "natwest.com", "finance", "London"),
    Subject("HSBC UK", "hsbc.co.uk", "finance", "London"),
    Subject("Aviva", "aviva.co.uk", "insurance", "London"),
    Subject("Legal & General", "legalandgeneral.com", "insurance", "London"),
    Subject("Prudential", "prudentialplc.com", "insurance", "London"),
    Subject("Tesco", "tesco.com", "retail", "UK"),
    Subject("Sainsbury's", "sainsburys.co.uk", "retail", "UK"),
    Subject("BT Group", "bt.com", "technology", "London"),
    Subject("Vodafone UK", "vodafone.co.uk", "technology", "UK"),
    Subject("Rolls-Royce", "rolls-royce.com", "defence", "UK"),
    Subject("BAE Systems", "baesystems.com", "defence", "UK"),
    Subject("AstraZeneca", "astrazeneca.com", "pharmaceutical", "UK"),
    Subject("GSK", "gsk.com", "pharmaceutical", "London"),
]

# --- NHS -------------------------------------------------------------------
# Highest shelf life of any cohort: patient records carry lifetime
# confidentiality duties, so Mosca's X is 25+ years here.

NHS: List[Subject] = [
    Subject("NHS England", "england.nhs.uk", "healthcare", "England"),
    Subject("NHS Digital", "digital.nhs.uk", "healthcare", "England"),
    Subject("Guy's and St Thomas'", "guysandstthomas.nhs.uk", "healthcare", "London"),
    Subject("Great Ormond Street", "gosh.nhs.uk", "healthcare", "London"),
    Subject("Royal Surrey", "royalsurrey.nhs.uk", "healthcare", "South East"),
    Subject("Oxford University Hospitals", "ouh.nhs.uk", "healthcare", "South East"),
    Subject("Manchester University NHS FT", "mft.nhs.uk", "healthcare", "North West"),
    Subject("Leeds Teaching Hospitals", "leedsth.nhs.uk", "healthcare", "Yorkshire"),
]

COHORTS: Dict[str, List[Subject]] = {
    "councils": UK_COUNCILS,
    "universities": UK_UNIVERSITIES,
    "listed": UK_LISTED,
    "nhs": NHS,
}

COHORT_LABELS = {
    "councils": "UK local authorities",
    "universities": "UK universities",
    "listed": "UK listed companies",
    "nhs": "NHS organisations",
}


def load_csv(path: str) -> List[Subject]:
    """Read subjects from a CSV with ``name,domain[,sector,region]``."""
    import csv

    subjects: List[Subject] = []
    with open(path, newline="", encoding="utf-8-sig") as handle:
        sample = handle.read(4096)
        handle.seek(0)
        has_header = "domain" in sample.split("\n", 1)[0].lower()
        reader = csv.DictReader(handle) if has_header else None

        if reader is not None:
            for row in reader:
                domain = (row.get("domain") or row.get("Domain") or "").strip()
                if not domain:
                    continue
                subjects.append(Subject(
                    name=(row.get("name") or row.get("Name") or domain).strip(),
                    domain=domain,
                    sector=(row.get("sector") or "general").strip() or "general",
                    region=(row.get("region") or "").strip(),
                ))
        else:
            handle.seek(0)
            for row in csv.reader(handle):
                if not row:
                    continue
                if len(row) == 1:
                    subjects.append(Subject(row[0].strip(), row[0].strip()))
                else:
                    subjects.append(Subject(
                        row[0].strip(), row[1].strip(),
                        row[2].strip() if len(row) > 2 else "general",
                        row[3].strip() if len(row) > 3 else "",
                    ))
    return subjects
