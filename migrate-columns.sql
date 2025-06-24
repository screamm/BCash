-- Lägg till saknade kolumner i befintliga tabeller
ALTER TABLE children ADD COLUMN is_active BOOLEAN DEFAULT 1;
ALTER TABLE parents ADD COLUMN is_active BOOLEAN DEFAULT 1;
ALTER TABLE parents ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;
ALTER TABLE parents ADD COLUMN locked_until DATETIME NULL;

-- Uppdatera befintliga rader till aktiva
UPDATE children SET is_active = 1 WHERE is_active IS NULL;
UPDATE parents SET is_active = 1 WHERE is_active IS NULL;
UPDATE parents SET failed_login_attempts = 0 WHERE failed_login_attempts IS NULL; 