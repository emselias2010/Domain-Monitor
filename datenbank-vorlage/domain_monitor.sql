
SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

CREATE TABLE `app_settings` (
  `setting_key` varchar(64) NOT NULL,
  `setting_value` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `app_settings` (`setting_key`, `setting_value`) VALUES
('notifications_enabled', '0'),
('registration_enabled', '1'),
('smtp_from', ''),
('smtp_host', ''),
('smtp_password', ''),
('smtp_port', '587'),
('smtp_tls', '1'),
('smtp_user', '');

CREATE TABLE `domains` (
  `id` int(11) NOT NULL,
  `protected_domain_id` int(11) NOT NULL,
  `domain` varchar(255) NOT NULL,
  `first_seen` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `dns_active` tinyint(1) DEFAULT 0,
  `website_active` tinyint(1) DEFAULT 0,
  `http_status` int(11) DEFAULT NULL,
  `title` varchar(500) DEFAULT '',
  `risk_score` int(11) DEFAULT 0,
  `final_url` varchar(1000) DEFAULT NULL,
  `redirected_to_protected` tinyint(1) DEFAULT 0,
  `login_found` tinyint(1) DEFAULT 0,
  `company_name_found` tinyint(1) DEFAULT 0,
  `company_name_header` tinyint(1) DEFAULT 0,
  `domain_for_sale` tinyint(1) NOT NULL DEFAULT 0,
  `registration_date` datetime DEFAULT NULL,
  `registrar` varchar(255) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `domain_ips` (
  `id` int(11) NOT NULL,
  `domain_id` int(11) NOT NULL,
  `ip_address` varchar(45) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `excluded_domains` (
  `id` int(11) NOT NULL,
  `domain` varchar(253) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `user_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `login_attempts` (
  `id` bigint(20) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `attempted_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `muted_domains` (
  `id` bigint(20) NOT NULL,
  `user_id` int(11) NOT NULL,
  `domain_id` bigint(20) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `protected_domains` (
  `id` int(11) NOT NULL,
  `domain` varchar(255) NOT NULL,
  `active` tinyint(1) DEFAULT 1,
  `created_at` datetime DEFAULT current_timestamp(),
  `user_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `scans` (
  `id` int(11) NOT NULL,
  `protected_domain_id` int(11) NOT NULL,
  `started_at` datetime DEFAULT current_timestamp(),
  `finished_at` datetime DEFAULT NULL,
  `candidates_count` int(11) DEFAULT 0,
  `registered_count` int(11) DEFAULT 0,
  `active_count` int(11) DEFAULT 0,
  `user_id` int(11) DEFAULT NULL,
  `error_message` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `scan_results` (
  `id` int(11) NOT NULL,
  `scan_id` int(11) NOT NULL,
  `domain_id` int(11) NOT NULL,
  `dns_active` tinyint(1) DEFAULT 0,
  `website_active` tinyint(1) DEFAULT 0,
  `http_status` int(11) DEFAULT NULL,
  `risk_score` int(11) DEFAULT 0,
  `finding_fingerprint` char(64) DEFAULT NULL,
  `ips_snapshot` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `scan_settings` (
  `id` int(11) NOT NULL,
  `enabled` tinyint(1) DEFAULT 0,
  `interval_hours` int(11) DEFAULT 24,
  `next_scan` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `user_id` int(11) DEFAULT NULL,
  `timezone` varchar(64) NOT NULL DEFAULT 'Europe/Vienna',
  `pause_weekends` tinyint(1) NOT NULL DEFAULT 0,
  `max_domains` int(11) NOT NULL DEFAULT 50000,
  `threat_intelligence_enabled` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `threat_intelligence` (
  `id` bigint(20) NOT NULL,
  `domain_id` bigint(20) NOT NULL,
  `source` varchar(64) NOT NULL,
  `status` varchar(32) NOT NULL,
  `category` varchar(64) DEFAULT NULL,
  `detections` int(11) NOT NULL DEFAULT 0,
  `reference_url` varchar(500) DEFAULT NULL,
  `checked_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(120) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('admin','user') NOT NULL DEFAULT 'user',
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `valid_until` datetime DEFAULT NULL,
  `email` varchar(254) DEFAULT NULL,
  `language` enum('de','en') NOT NULL DEFAULT 'de',
  `notifications_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `plan` enum('free','pro') NOT NULL DEFAULT 'free',
  `pro_until` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `users` (`id`, `username`, `password_hash`, `role`, `active`, `created_at`, `valid_until`, `email`, `language`, `notifications_enabled`, `plan`, `pro_until`) VALUES
(1, 'admin', '$2y$10$uBasIjzYrvQqcKWryTRgfON3qcYIXI.hRW1KX.dB.mqxuCD5vbCby', 'admin', 1, NOW(), NULL, 'admin@example.com', 'de', 0, 'free', NULL);

CREATE TABLE `user_scan_jobs` (
  `id` bigint(20) NOT NULL,
  `user_id` int(11) NOT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'starting',
  `pid` int(11) DEFAULT NULL,
  `progress_file` varchar(500) NOT NULL,
  `log_file` varchar(500) NOT NULL,
  `started_at` datetime NOT NULL,
  `finished_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE `app_settings`
  ADD PRIMARY KEY (`setting_key`);

ALTER TABLE `domains`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_domains_user_domain` (`user_id`,`domain`),
  ADD KEY `protected_domain_id` (`protected_domain_id`);

ALTER TABLE `domain_ips`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_domain_ip` (`domain_id`,`ip_address`);

ALTER TABLE `excluded_domains`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `domain` (`domain`);

ALTER TABLE `login_attempts`
  ADD PRIMARY KEY (`id`),
  ADD KEY `ip_address` (`ip_address`,`attempted_at`);

ALTER TABLE `muted_domains`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_muted_user_domain` (`user_id`,`domain_id`),
  ADD KEY `idx_muted_domain` (`domain_id`);

ALTER TABLE `protected_domains`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_protected_domains_user_domain` (`user_id`,`domain`);

ALTER TABLE `scans`
  ADD PRIMARY KEY (`id`),
  ADD KEY `protected_domain_id` (`protected_domain_id`);

ALTER TABLE `scan_results`
  ADD PRIMARY KEY (`id`),
  ADD KEY `scan_id` (`scan_id`),
  ADD KEY `domain_id` (`domain_id`);

ALTER TABLE `scan_settings`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `threat_intelligence`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_threat_domain_source` (`domain_id`,`source`),
  ADD KEY `idx_threat_domain_checked` (`domain_id`,`checked_at`);

ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `uq_users_email` (`email`);

ALTER TABLE `user_scan_jobs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

ALTER TABLE `domains`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `domain_ips`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `excluded_domains`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=20;

ALTER TABLE `login_attempts`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=22;

ALTER TABLE `muted_domains`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

ALTER TABLE `protected_domains`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=46;

ALTER TABLE `scans`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `scan_results`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `scan_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=28;

ALTER TABLE `threat_intelligence`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=37;

ALTER TABLE `user_scan_jobs`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

ALTER TABLE `domains`
  ADD CONSTRAINT `domains_ibfk_1` FOREIGN KEY (`protected_domain_id`) REFERENCES `protected_domains` (`id`) ON DELETE CASCADE;

ALTER TABLE `domain_ips`
  ADD CONSTRAINT `domain_ips_ibfk_1` FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE CASCADE;

ALTER TABLE `scans`
  ADD CONSTRAINT `scans_ibfk_1` FOREIGN KEY (`protected_domain_id`) REFERENCES `protected_domains` (`id`) ON DELETE CASCADE;

ALTER TABLE `scan_results`
  ADD CONSTRAINT `scan_results_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `scan_results_ibfk_2` FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE CASCADE;

ALTER TABLE `user_scan_jobs`
  ADD CONSTRAINT `fk_user_scan_jobs_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
