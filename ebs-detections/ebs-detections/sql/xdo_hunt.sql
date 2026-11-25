-- =====================================================================
-- xdo_hunt: CVE-2025-61882 database hunt for malicious XSL templates
-- Source: GTIG/Mandiant and CrowdStrike hunting guidance
-- Status in this project: AUTHORED & REASONED, NOT DYNAMICALLY TESTED
--   (no licensed EBS database in the lab)
-- Pre-disclosure class: E (EBS-specific)
-- Run as a read-only user against the EBS APPS schema.
-- =====================================================================

-- 1) Templates whose code starts with TMP or DEF (where payloads were stored)
SELECT template_code,
       application_short_name,
       template_type_code,
       creation_date,
       created_by,
       last_update_date
FROM   xdo_templates_b
WHERE  template_code LIKE 'TMP%'
   OR  template_code LIKE 'DEF%'
ORDER  BY creation_date DESC;

-- 2) Matching LOB records holding the template content
SELECT lob_code,
       lob_type,
       file_name,
       creation_date,
       last_update_date
FROM   xdo_lobs
WHERE  lob_code LIKE 'TMP%'
   OR  lob_code LIKE 'DEF%'
ORDER  BY creation_date DESC;

-- 3) Triage: any template created inside the exploitation window
SELECT template_code, creation_date, created_by
FROM   xdo_templates_b
WHERE  creation_date BETWEEN DATE '2025-07-01' AND DATE '2025-10-15'
ORDER  BY creation_date;
