CREATE TABLE IF NOT EXISTS `#__dracoinsomnis_events` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime NOT NULL,
  `ip` varchar(45) NOT NULL,
  `remote_addr` varchar(45) NOT NULL,
  `endpoint` varchar(40) NOT NULL,
  `score` smallint unsigned NOT NULL,
  `verdict` varchar(10) NOT NULL,
  `reasons` varchar(190) NOT NULL DEFAULT '',
  `user_agent` varchar(255) NOT NULL DEFAULT '',
  `fields` text,
  PRIMARY KEY (`id`),
  KEY `ip_created` (`ip`, `created_at`),
  KEY `verdict_created` (`verdict`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `#__dracoinsomnis_blocks` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `kind` varchar(8) NOT NULL,
  `value` varchar(190) NOT NULL,
  `reason` varchar(190) NOT NULL DEFAULT '',
  `created_at` datetime NOT NULL,
  `until_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `lookup` (`kind`, `value`, `until_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `#__dracoinsomnis_cache` (
  `k` varchar(190) NOT NULL,
  `n` int unsigned NOT NULL DEFAULT 0,
  `v` varchar(255) NOT NULL DEFAULT '',
  `expires` int unsigned NOT NULL,
  PRIMARY KEY (`k`),
  KEY `expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;
