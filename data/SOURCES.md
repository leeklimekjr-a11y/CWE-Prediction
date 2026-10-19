# Official source collection

`upstream/cvelistV5/` contains official CVE Program records; `upstream/cve-schema/` contains their record schemas. Both are Git submodules pinned by the parent repository.

`raw/nvd-cve/<snapshot>/` contains all annual NVD JSON 2.0 feeds from 2002 onward, including the earlier CVEs carried in the initial feed. Original records retain descriptions, references, CWE labels, CVSS metrics, applicability configurations, and other published fields without column filtering.

`raw/cpe/` holds the official CPE dictionary; `raw/cpematch/` holds match criteria and their platform mappings. These complement CVE applicability fields. Preserve the logical configuration structure when interpreting affected products.

`raw/cwe/` contains the complete current CWE catalog and schema, including weaknesses, categories, views, and relationship context. `raw/capec/` contains the related attack-pattern catalog and schema. Extracted catalog XML is retained beside its source ZIP.

`manifests/` records acquisition windows, source URLs, file sizes, hashes, validation details, and source Git commits. Downloads are acquired sequentially, not as one transactionally consistent upstream snapshot. Unavailable or absent upstream fields are not invented.

Bulk files under `raw/`, `cache/`, and `derived/` are ignored by ordinary Git commits. Commit the tooling, source documentation, manifests, and submodule pins. Large snapshots require separate artifact storage if they must be shared.

Run `python3 data/scripts/sync-cwe-data.py --repo .` for a new snapshot; use `--snapshot NAME` to resume a recorded one. Existing submodules retain their pins unless `--update-submodules` is supplied.

Scope is the current public source records/catalogs at acquisition time, not every historical revision, every external referenced document, or every security taxonomy. NVD change history, historical CWE/CAPEC releases, ATT&CK, KEV, EPSS, and external product metadata are separate acquisitions and are not claimed included. This tool does not restore historical CSV bytes.
