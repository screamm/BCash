-- Lägg till testbarn
INSERT OR IGNORE INTO children (name, username, password, balance) VALUES
('Anna', 'anna', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 150),
('Erik', 'erik', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 250),
('Lila', 'lila', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 75);

-- Lägg till testförälder
INSERT OR IGNORE INTO parents (name, username, password) VALUES
('Mamma', 'mamma', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi');

-- Lägg till testtransaktioner
INSERT OR IGNORE INTO transactions (child_id, amount, description, type, created_by) VALUES
(1, 50, 'Veckopeng', 'allowance', 1),
(1, -25, 'Köpte godis', 'purchase', 1),
(2, 100, 'Städade rummet', 'chore', 1),
(2, -50, 'Sparade till leksak', 'savings', 1),
(3, 25, 'Extra pengar', 'bonus', 1),
(3, -10, 'Köpte klistermärken', 'purchase', 1); 