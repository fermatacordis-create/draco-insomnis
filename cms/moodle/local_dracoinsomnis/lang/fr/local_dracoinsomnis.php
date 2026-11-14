<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'fr' (generated from i18n/fr.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Automatique : {$a} tentatives de robot en 24 h';
$string['block'] = 'Bloquer';
$string['blockadd'] = 'Bloquer une adresse ou une plage';
$string['blockadd_desc'] = 'Jamais un administrateur, ni votre propre adresse. Plages pas plus larges que /16 (IPv4) ou /32 (IPv6).';
$string['blockdays'] = 'Pendant';
$string['blockdone'] = 'Bloqué : {$a}';
$string['blockedtext'] = 'Cette requête a été arrêtée pour des raisons de sécurité. Si vous pensez qu’il s’agit d’une erreur, contactez le propriétaire du site.';
$string['blockedtitle'] = 'Requête bloquée';
$string['blockrefused'] = 'Rien n’a été bloqué : la valeur n’est pas valide, appartient à un administrateur ou est votre propre adresse.';
$string['blocks'] = 'Adresses bloquées';
$string['blockvalue'] = 'IP ou plage (p. ex. 203.0.113.0/24)';
$string['coldata'] = 'Données';
$string['coldate'] = 'Date (UTC)';
$string['colemail'] = 'E-mail';
$string['colip'] = 'Adresse';
$string['colmessage'] = 'Message';
$string['colreason'] = 'Motif';
$string['colsigns'] = 'Signes';
$string['coluntil'] = 'Jusqu’au (UTC)';
$string['colvalue'] = 'Adresse ou e-mail';
$string['colverdict'] = 'Verdict';
$string['colwhere'] = 'Où';
$string['days15'] = '15 jours';
$string['days30'] = '30 jours';
$string['days7'] = '7 jours';
$string['days90'] = '90 jours';
$string['done'] = 'Fait.';
$string['dracoinsomnis:bypassfirewall'] = 'Contourner le pare-feu Draco Insomnis';
$string['events'] = 'Dernières tentatives suspectes';
$string['events_help'] = 'Gardées 90 jours. Jamais de mots de passe. Le CSV d’une adresse contient tout ce qu’elle a fait, prêt à joindre à un signalement d’abus auprès de son fournisseur réseau.';
$string['evidence'] = 'Draco Insomnis : blocages et preuves';
$string['forever'] = 'Pour toujours';
$string['geo'] = 'Pays';
$string['geo_desc'] = 'Vos visiteurs peuvent venir de nombreux pays, et un attaquant change de pays avec un VPN. Filtrez seulement la connexion, l’inscription et les formulaires, et commencez par « Journal seulement ». Les administrateurs du site, les personnes que vous laissez passer et les moteurs de recherche ne sont jamais filtrés. Le pare-feu doit être actif (journal ou blocage).';
$string['geoaction'] = 'Que faire';
$string['geocountries'] = 'Pays (codes à deux lettres, p. ex. ES, FR, DE)';
$string['geocredit'] = 'Géolocalisation IP par DB-IP (db-ip.com, CC BY 4.0), téléchargée quand vous activez le filtre et consultée sur votre propre serveur : aucune adresse n’est envoyée nulle part.';
$string['geomode'] = 'Filtre';
$string['geoonly'] = 'Seulement les pays listés';
$string['georefuse'] = 'Refuser les pays listés';
$string['geoscope'] = 'Où';
$string['geosensitive'] = 'Connexion, inscription et formulaires (recommandé)';
$string['geosite'] = 'Tout le site';
$string['headers'] = 'En-têtes de sécurité';
$string['headers_desc'] = 'Sur les pages : pas de devinette du type de fichier, pas d’affichage dans d’autres sites, moins de données de provenance, ni caméra, ni micro, ni position pour le contenu intégré. Jamais un en-tête que Moodle envoie déjà.';
$string['hsts'] = 'Forcer HTTPS pendant 6 mois (HSTS)';
$string['hsts_desc'] = 'Seulement si tout le site fonctionne en HTTPS et le restera : les navigateurs s’en souviennent et refusent HTTP jusqu’à expiration.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Arrête les fausses inscriptions sans captcha : les robots n’obtiennent pas de compte, et chaque tentative suspecte est gardée 90 jours comme preuve pour un signalement d’abus. Rien n’est jamais renvoyé à l’attaquant.</p><p>Adresses bloquées et dernières tentatives : <a href="{$a}">Draco Insomnis : blocages et preuves</a>.</p>';
$string['modeblock'] = 'Bloquer';
$string['modelog'] = 'Journal seulement : noter ce qui serait arrêté';
$string['modeoff'] = 'Désactivé';
$string['nets'] = 'Réseaux de serveurs loués';
$string['nets_desc'] = 'Une plage par ligne (CIDR), ajoutée à celles que l’extension connaît déjà. Figurer sur cette liste ajoute seulement des points : à elle seule, elle ne fait jamais de quelqu’un un robot.';
$string['noblocks'] = 'Rien n’est bloqué pour le moment.';
$string['noevents'] = 'Rien pour l’instant.';
$string['noreviews'] = 'Aucune demande.';
$string['notdone'] = 'Impossible pour cette adresse.';
$string['pace'] = 'Limite de rythme anti-copie';
$string['pace_desc'] = 'Plus de pages par minute qu’une personne n’en lit reçoivent « 429 Trop de requêtes » jusqu’à la fin de la minute. Les utilisateurs connectés, vos propres adresses et les moteurs de recherche vérifiés par DNS (Google, Bing, Apple, Yandex) ne sont jamais limités. Les appels AJAX, les services web et les fichiers ne comptent pas.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Adresses et e-mails bloqués pour un temps, par le blocage automatique ou par un administrateur.';
$string['privacy:metadata:blocks:value'] = 'L’adresse IP ou l’e-mail bloqué.';
$string['privacy:metadata:events'] = 'Tentatives suspectes (fausses inscriptions, attaques, aspiration), gardées 90 jours comme preuves pour des signalements d’abus. Non liées aux comptes Moodle. Jamais de mots de passe.';
$string['privacy:metadata:events:fields'] = 'Nom d’utilisateur, e-mail et page de provenance envoyés avec la tentative.';
$string['privacy:metadata:events:ip'] = 'L’adresse IP d’où venait la tentative.';
$string['privacy:metadata:events:timecreated'] = 'Quand la tentative a eu lieu.';
$string['privacy:metadata:events:useragent'] = 'Le nom du navigateur ou du programme qu’elle a envoyé.';
$string['proxy'] = 'Adresse du visiteur';
$string['proxy_desc'] = 'Laissez « Adresse de connexion » sauf si le site est derrière un proxy : n’importe qui peut falsifier un en-tête.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'L’en-tête est ignoré : cette connexion (<code>{$a}</code>) ne vient ni de Cloudflare ni d’un proxy de confiance. Si votre proxy est sur Internet, ajoutez ses adresses dans « Proxys de confiance ».';
$string['proxynone'] = 'Adresse de connexion (recommandé)';
$string['proxyxff'] = 'Autre proxy (X-Forwarded-For)';
$string['pwdbreached'] = 'Refuser les mots de passe trouvés dans des fuites de données';
$string['pwdbreached_desc'] = 'Interroge Have I Been Pwned avec k-anonymat : seuls 5 caractères du SHA-1 du mot de passe quittent le site, jamais le mot de passe. Si le service ne répond pas en 3 secondes, le mot de passe est accepté. Moodle l’applique tant que « Politique de mot de passe » est activée (Administration du site > Sécurité > Règles de sécurité du site).';
$string['pwdbreachedrefused'] = 'Ce mot de passe figure dans des fuites de données connues, les attaquants l’essaient donc en premier. Choisissez-en un autre, s’il vous plaît.';
$string['pwdmin'] = 'Longueur minimale du mot de passe';
$string['pwdmin_desc'] = 'De 8 à 64 caractères ; 0 laisse seulement la règle de Moodle. Appliqué tant que « Politique de mot de passe » est activée.';
$string['pwdshort'] = 'Le mot de passe doit avoir au moins {$a} caractères.';
$string['rateip'] = 'Pages par minute, par adresse';
$string['ratenet'] = 'Pages par minute, par réseau';
$string['ratenet_desc'] = 'Un réseau /24 en IPv4 ou /64 en IPv6 : ce qu’obtient un aspirateur de site qui change d’adresses voisines.';
$string['rejected'] = 'L’inscription n’a pas pu être finalisée.';
$string['review1'] = 'Laisser passer 24 heures';
$string['review30'] = '30 jours';
$string['review7'] = '7 jours';
$string['reviewapproved'] = 'Laisser passer';
$string['reviewattacker'] = 'Attaquant : bloqué';
$string['reviewattackerbtn'] = 'Attaquant';
$string['reviewbody'] = 'Un visiteur arrêté par le pare-feu demande une vérification. Ouvrez la page Draco Insomnis pour le laisser passer ou non.';
$string['reviewbutton'] = 'Demander une vérification';
$string['reviewdenied'] = 'Refusée';
$string['reviewdeny'] = 'Refuser';
$string['reviewemail'] = 'Votre e-mail';
$string['reviewmessage'] = 'Que faisiez-vous ?';
$string['reviewreason'] = 'Vérification : {$a}';
$string['reviews'] = 'Demandes de vérification';
$string['reviewsenttext'] = 'Merci. Le responsable du site va l’examiner et, s’il s’agit d’une erreur, vous laissera passer.';
$string['reviewsenttitle'] = 'Demande envoyée';
$string['reviewshelp'] = 'Les personnes arrêtées par le pare-feu peuvent le demander depuis la page de blocage. Laissez-les passer un moment si c’était une erreur. Draco ne leur écrit jamais : répondez depuis votre propre messagerie si vous le souhaitez.';
$string['reviewsubject'] = '[{$a}] Quelqu’un vous demande de vérifier un blocage du pare-feu';
$string['shield'] = 'Protéger l’auto-inscription';
$string['shield_desc'] = 'Ajoute un piège invisible et un tampon de page signé au formulaire d’inscription (auto-inscription par e-mail). Les robots n’obtiennent pas de compte ; trois tentatives de robot en un jour bloquent l’adresse pendant une semaine.';
$string['summary'] = 'Pare-feu : 7 derniers jours';
$string['summaryips'] = 'Adresses les plus actives :';
$string['summaryline'] = '{$a->total} attaques vues, {$a->blocked} bloquées.';
$string['summarywhat'] = 'Quoi :';
$string['taskcleanup'] = 'Draco Insomnis : supprimer les anciennes preuves et les blocages terminés';
$string['test'] = 'Tester le pare-feu';
$string['testblocked'] = 'Ça marche : une injection dans la base de données a été reconnue et bloquée (403).';
$string['testhelp'] = 'Envoie au site une requête inoffensive en forme d’attaque et vous dit ce qui s’est passé. Elle n’est pas journalisée.';
$string['testlogged'] = 'Ça marche : une injection dans la base de données a été reconnue. En « Journaliser seulement », elle est notée mais pas arrêtée ; passez à « Bloquer » quand vous êtes prêt.';
$string['testnone'] = 'L’attaque de test n’a pas été reconnue. Merci de le signaler à Draco Insomnis.';
$string['testoff'] = 'Le pare-feu est désactivé : activez-le, enregistrez, puis testez à nouveau.';
$string['testunreachable'] = 'Le test n’a pas pu atteindre le site depuis le serveur lui-même (certains hébergeurs ne le permettent pas). Le pare-feu peut quand même fonctionner : regardez les dernières tentatives.';
$string['testupstream'] = 'Le test a été arrêté avant d’atteindre Moodle, par le pare-feu de l’hébergeur. Bien : deux couches.';
$string['trusted'] = 'Proxys de confiance';
$string['trusted_desc'] = 'Seules les connexions venant de ces adresses peuvent fixer l’adresse du visiteur par un en-tête. Une adresse ou une plage par ligne. Vide : ce serveur et les réseaux privés. Les plages de Cloudflare sont déjà connues.';
$string['unblock'] = 'Débloquer';
$string['unblocked'] = 'Adresse débloquée.';
$string['waf'] = 'Pare-feu';
$string['waf_desc'] = 'Arrête les requêtes qui ont la forme d’une attaque (injection dans la base de données, lecture de fichiers du serveur, exécution de code, scripts dans les liens) et les scanners comme sqlmap ou Nikto. Commencez par « Journal seulement » et passez à « Bloquer » après quelques jours. Cinq attaques en 10 minutes bloquent l’adresse pendant une semaine ; les adresses bloquées peuvent toujours lire le site, mais pas envoyer ni se connecter. Les administrateurs du site et les utilisateurs ayant « Contourner le pare-feu Draco Insomnis » ne sont jamais inspectés. Sortie de secours : define(\'DRACO_WAF_OFF\', true); dans config.php.';
$string['wafblock'] = 'Pare-feu : {$a} attaques en 10 minutes';
$string['yourip'] = 'Votre adresse telle que l’extension la voit : <code>{$a->ip}</code> (adresse de connexion : <code>{$a->remote}</code>). Si le site est derrière Cloudflare ou un autre proxy et qu’elles diffèrent de votre adresse réelle, choisissez l’option correspondante dans « Adresse du visiteur ».';
