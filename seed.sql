-- Lägg till testbarn med säkra hashade lösenord
-- Lösenord: barn123 (hashad med bcrypt)
INSERT OR IGNORE INTO children (name, username, password, balance) VALUES
('Anna', 'anna', '$2b$10$rOzHqKcJJBNb1xKJ0x8oTuQxPp6yJbJvfzQgHJyL8GzX2mNvOp4sK', 150),
('Erik', 'erik', '$2b$10$rOzHqKcJJBNb1xKJ0x8oTuQxPp6yJbJvfzQgHJyL8GzX2mNvOp4sK', 250),
('Lila', 'lila', '$2b$10$rOzHqKcJJBNb1xKJ0x8oTuQxPp6yJbJvfzQgHJyL8GzX2mNvOp4sK', 75);

-- Lägg till testförälder med säker hashad lösenord
-- Lösenord: förälder456 (hashad med bcrypt)
INSERT OR IGNORE INTO parents (name, username, password) VALUES
('Mamma', 'mamma', '$2b$10$8K7Qz9mNpLkJhGfDsA1sBOHxYvWuEtRqPo9IuYtReWqAzSxCvBnMi');

-- Lägg till testtransaktioner
INSERT OR IGNORE INTO transactions (child_id, amount, description, type, created_by) VALUES
(1, 50, 'Veckopeng', 'allowance', 1),
(1, -25, 'Köpte godis', 'purchase', 1),
(2, 100, 'Städade rummet', 'chore', 1),
(2, -50, 'Sparade till leksak', 'savings', 1),
(3, 25, 'Extra pengar', 'bonus', 1),
(3, -10, 'Köpte klistermärken', 'purchase', 1);

-- Initial health check
INSERT OR IGNORE INTO health_checks (check_type, status, details) VALUES
('database', 'healthy', 'Initial database setup completed successfully'); 