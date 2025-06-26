-- Lägg till riktiga användare med säkra hashade lösenord
-- Förälderkonto: PappaDavid (lösenord: barbapappa3386)
INSERT OR IGNORE INTO parents (name, username, password) VALUES
('PappaDavid', 'PappaDavid', '$2b$12$8mJ2LJS1KolfODBn3G10C.oaATKP1lc/Kx6dLDieL6kN6J7DJkLL2');

-- Barn: Alexander och Alicia (lösenord: cocodrilobombino)
INSERT OR IGNORE INTO children (name, username, password, balance) VALUES
('Alexander', 'Alexander', '$2b$12$IT/bwZ4hQoOuZ.6KK.G.Aeaa7AAt4214AyeCkCAGw70XkCEXFhsgC', 500),
('Alicia', 'Alicia', '$2b$12$lae4qruRgkHviqbCOfTsIuvQxdIVI.97CEIbu/Lr9TlxuG7iTRiMu', 350);

-- Lägg till initiala transaktioner för barnen
INSERT OR IGNORE INTO transactions (child_id, amount, description, type, created_by) VALUES
(1, 200, 'Startsaldo Alexander', 'allowance', 1),
(1, 150, 'Veckopeng', 'allowance', 1),
(1, 100, 'Extra belöning', 'bonus', 1),
(1, 50, 'Städade rummet', 'chore', 1),
(2, 150, 'Startsaldo Alicia', 'allowance', 1),
(2, 100, 'Veckopeng', 'allowance', 1),
(2, 75, 'Hjälpte till i köket', 'chore', 1),
(2, 25, 'Extra pengar', 'bonus', 1);

-- Initial health check
INSERT OR IGNORE INTO health_checks (check_type, status, details) VALUES
('database', 'healthy', 'Database setup completed with real users successfully'); 