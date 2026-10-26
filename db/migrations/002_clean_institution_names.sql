-- ============================================================================
-- AUTHENTIX — Migration 002: Clean Institution Display Names
-- Removes baked-in '[SYNTHETIC DEMO]' suffixes from persisted institution names
-- while preserving `is_synthetic_demo = 1` metadata flags in SQLite so sample
-- records are truthfully labelled only when development/demo mode is active.
-- ============================================================================

UPDATE institutions
SET name = TRIM(REPLACE(name, '[SYNTHETIC DEMO]', ''))
WHERE name LIKE '%[SYNTHETIC DEMO]%';

UPDATE sandbox_issuer_registry
SET institution_name = TRIM(REPLACE(institution_name, '[SYNTHETIC DEMO]', ''))
WHERE institution_name LIKE '%[SYNTHETIC DEMO]%';
