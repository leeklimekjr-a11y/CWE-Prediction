# CWE-Prediction
Investigation into software defect co-occurence

# Premise
When examining defects found in a platform/product/service (called a "target" going forward), we regularly find patterns of commonly-paired CWEs.  The most anectdotal of these is the commonly found xSS and xSRF.  These are different bugs, but if you find one you'll likely find the other.  And, by knowing that fact, one is better informed about what to look for when hunting for bugs.

# Hypothesis
Defect co-occurence is not purely random, but are at least partially subject to the training/biases/ptractices of the developers who created them.  THerefore, there is a passive, latent connection between specific CWEs.  If that is true, then there is a finite set of CWEs {X,Y} in which if X is found in a target then there is a non-zero probability with a Lift > 1.0 that Y also exists within the same target.

# Roadmap
1. ETL NIST NVDB and MITRE taxonomies (CPE, CWE, etc)
2. Process published CVEs and tag each with a target label to quanitze CVEs into the product on which they were found, this should result in multiple CVEs in each bucket.  A temporal sliding window might need to be employed.  The submission date only points to the discovery of a defect, not to its creation, and we're focusing on creation.
3. Perform Associative Analysis to identify requent groupings of co-occuring CWEs
4. Define metrics for defect similarity (possibly traversal distance)
5. Add filters to account parent-child-ancestor relationships
6. Define an entrypy-type metric to describe the information we gain through a rule
7. Define a metric for the usefulness of a rule (does knowing the potential existence of a defect increase the changces of finding it)
8. Investigate thresholds for Lift, COnfidence, Precision, and others
9. Investigate causality
10. Cross-validate using existing CWE buckets
11. Investigate using other metadata (such las language, LOC, who knows what else)


