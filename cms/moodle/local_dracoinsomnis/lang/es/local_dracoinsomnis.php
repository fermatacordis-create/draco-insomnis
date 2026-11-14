<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'es' (generated from i18n/es.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Automático: {$a} intentos de bot en 24 h';
$string['block'] = 'Bloquear';
$string['blockadd'] = 'Bloquear una dirección o un rango';
$string['blockadd_desc'] = 'Nunca un administrador ni tu propia dirección. Rangos no más amplios que /16 (IPv4) o /32 (IPv6).';
$string['blockdays'] = 'Durante';
$string['blockdone'] = 'Bloqueado: {$a}';
$string['blockedtext'] = 'Esta petición se ha detenido por seguridad. Si crees que es un error, contacta con el dueño de la web.';
$string['blockedtitle'] = 'Petición bloqueada';
$string['blockrefused'] = 'No se ha bloqueado: el dato no es válido, es de un administrador o es tu propia IP.';
$string['blocks'] = 'Direcciones bloqueadas';
$string['blockvalue'] = 'IP o rango (p. ej. 203.0.113.0/24)';
$string['coldata'] = 'Datos';
$string['coldate'] = 'Fecha (UTC)';
$string['colemail'] = 'Correo';
$string['colip'] = 'Dirección';
$string['colmessage'] = 'Mensaje';
$string['colreason'] = 'Motivo';
$string['colsigns'] = 'Señales';
$string['coluntil'] = 'Hasta (UTC)';
$string['colvalue'] = 'Dirección o correo';
$string['colverdict'] = 'Veredicto';
$string['colwhere'] = 'Dónde';
$string['days15'] = '15 días';
$string['days30'] = '30 días';
$string['days7'] = '7 días';
$string['days90'] = '90 días';
$string['done'] = 'Hecho.';
$string['dracoinsomnis:bypassfirewall'] = 'Saltarse el cortafuegos de Draco Insomnis';
$string['events'] = 'Últimos intentos sospechosos';
$string['events_help'] = 'Se guardan 90 días. Nunca contraseñas. El CSV de una dirección reúne todo lo que hizo, listo para adjuntarlo a una denuncia a su proveedor de red.';
$string['evidence'] = 'Draco Insomnis: bloqueos y evidencias';
$string['forever'] = 'Para siempre';
$string['geo'] = 'Países';
$string['geo_desc'] = 'Puede que tus visitantes vengan de muchos países, y un atacante cambia de país con una VPN. Filtra solo el inicio de sesión, el registro y los formularios, y empieza con «Solo registrar». Los administradores del sitio, las personas a las que dejas pasar y los buscadores nunca se filtran. Necesita el cortafuegos encendido (registrar o bloquear).';
$string['geoaction'] = 'Qué hacer';
$string['geocountries'] = 'Países (códigos de dos letras, p. ej. ES, FR, DE)';
$string['geocredit'] = 'Geolocalización IP de DB-IP (db-ip.com, CC BY 4.0), descargada al encender el filtro y consultada en tu propio servidor: no se envía ninguna dirección a ningún sitio.';
$string['geomode'] = 'Filtro';
$string['geoonly'] = 'Solo los países de la lista';
$string['georefuse'] = 'Rechazar los países de la lista';
$string['geoscope'] = 'Dónde';
$string['geosensitive'] = 'Acceso, altas y formularios (recomendado)';
$string['geosite'] = 'Todo el sitio';
$string['headers'] = 'Cabeceras de seguridad';
$string['headers_desc'] = 'En las páginas: sin adivinar tipos de archivo, sin que otros sitios las incrusten, menos datos de procedencia y sin cámara, micrófono ni ubicación para el contenido incrustado. Nunca una que Moodle ya envíe.';
$string['hsts'] = 'Forzar HTTPS durante 6 meses (HSTS)';
$string['hsts_desc'] = 'Solo si todo el sitio funciona con HTTPS y va a seguir así: los navegadores lo recuerdan y rechazan HTTP hasta que caduque.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Para los registros falsos sin captchas: los bots no consiguen cuenta y cada intento sospechoso se guarda 90 días como prueba para una denuncia de abuso. Nunca se envía nada al atacante.</p><p>Direcciones bloqueadas y últimos intentos: <a href="{$a}">Draco Insomnis: bloqueos y evidencias</a>.</p>';
$string['modeblock'] = 'Bloquear';
$string['modelog'] = 'Solo registrar lo que pararía';
$string['modeoff'] = 'Apagado';
$string['nets'] = 'Redes de servidores de alquiler';
$string['nets_desc'] = 'Un rango por línea (CIDR), que se suma a los que el plugin ya conoce. Estar en esta lista solo suma puntos: por sí sola nunca convierte a nadie en bot.';
$string['noblocks'] = 'Ahora mismo no hay nada bloqueado.';
$string['noevents'] = 'Todavía nada.';
$string['noreviews'] = 'No hay solicitudes.';
$string['notdone'] = 'No se ha podido hacer con esa dirección.';
$string['pace'] = 'Límite de ritmo anti-copia';
$string['pace_desc'] = 'Quien pide más páginas por minuto de las que lee una persona recibe «429 Demasiadas peticiones» hasta que acaba el minuto. Los usuarios con sesión iniciada, tus propias direcciones y los buscadores verificados por DNS (Google, Bing, Apple, Yandex) nunca se limitan. Las llamadas AJAX, los servicios web y los archivos no cuentan.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Direcciones y correos bloqueados durante un tiempo, por el bloqueo automático o por un administrador.';
$string['privacy:metadata:blocks:value'] = 'La dirección IP o el correo bloqueado.';
$string['privacy:metadata:events'] = 'Intentos sospechosos (registros falsos, ataques, copia masiva), guardados 90 días como prueba para denuncias de abuso. No están ligados a cuentas de Moodle. Nunca contraseñas.';
$string['privacy:metadata:events:fields'] = 'Nombre de usuario, correo y página de procedencia enviados con el intento.';
$string['privacy:metadata:events:ip'] = 'La dirección IP de la que vino el intento.';
$string['privacy:metadata:events:timecreated'] = 'Cuándo ocurrió el intento.';
$string['privacy:metadata:events:useragent'] = 'El nombre del navegador o del programa que envió.';
$string['proxy'] = 'IP del visitante';
$string['proxy_desc'] = 'Deja «Dirección de la conexión» salvo que el sitio esté detrás de un proxy: cualquiera puede falsificar una cabecera.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'La cabecera se ignora: esta conexión (<code>{$a}</code>) no viene de Cloudflare ni de un proxy de confianza. Si tu proxy está en internet, añade sus direcciones en «Proxies de confianza».';
$string['proxynone'] = 'Dirección de la conexión (recomendado)';
$string['proxyxff'] = 'Otro proxy (X-Forwarded-For)';
$string['pwdbreached'] = 'Rechazar contraseñas filtradas';
$string['pwdbreached_desc'] = 'Pregunta a Have I Been Pwned con k-anonimato: del sitio solo salen 5 caracteres del SHA-1 de la contraseña, nunca la contraseña. Si el servicio no responde en 3 segundos, la contraseña se acepta. Moodle lo aplica mientras «Política de contraseñas» esté activada (Administración del sitio > Seguridad > Políticas de seguridad del sitio).';
$string['pwdbreachedrefused'] = 'Esta contraseña aparece en filtraciones de datos conocidas, así que los atacantes la prueban primero. Elige otra, por favor.';
$string['pwdmin'] = 'Longitud mínima de la contraseña';
$string['pwdmin_desc'] = 'De 8 a 64 caracteres; con 0 queda solo la regla propia de Moodle. Se aplica mientras «Política de contraseñas» esté activada.';
$string['pwdshort'] = 'La contraseña debe tener al menos {$a} caracteres.';
$string['rateip'] = 'Páginas por minuto, por dirección';
$string['ratenet'] = 'Páginas por minuto, por red';
$string['ratenet_desc'] = 'Una red /24 en IPv4 o /64 en IPv6: lo que usa un copiador cuando va cambiando entre direcciones vecinas.';
$string['rejected'] = 'No se ha podido completar el registro.';
$string['review1'] = 'Dejar pasar 24 horas';
$string['review30'] = '30 días';
$string['review7'] = '7 días';
$string['reviewapproved'] = 'Dejar pasar';
$string['reviewattacker'] = 'Atacante: bloqueado';
$string['reviewattackerbtn'] = 'Atacante';
$string['reviewbody'] = 'Un visitante parado por el cortafuegos pide una revisión. Abre la página de Draco Insomnis para dejarle pasar o no.';
$string['reviewbutton'] = 'Pedir una revisión';
$string['reviewdenied'] = 'Denegada';
$string['reviewdeny'] = 'Denegar';
$string['reviewemail'] = 'Tu correo';
$string['reviewmessage'] = '¿Qué estabas haciendo?';
$string['reviewreason'] = 'Revisión: {$a}';
$string['reviews'] = 'Solicitudes de revisión';
$string['reviewsenttext'] = 'Gracias. El responsable del sitio lo revisará y, si fue un error, te dejará pasar.';
$string['reviewsenttitle'] = 'Solicitud enviada';
$string['reviewshelp'] = 'Quien fue detenido por el cortafuegos puede pedirlo desde la página de bloqueo. Déjale pasar un tiempo si fue un error. Draco nunca le escribe: contéstale desde tu correo si quieres.';
$string['reviewsubject'] = '[{$a}] Alguien pide que revises un bloqueo del cortafuegos';
$string['shield'] = 'Proteger el autorregistro';
$string['shield_desc'] = 'Añade una trampa invisible y un sello firmado de la página al formulario de registro (autorregistro por correo). Los bots no consiguen cuenta; tres intentos de bot en un día bloquean la dirección una semana.';
$string['summary'] = 'Cortafuegos: últimos 7 días';
$string['summaryips'] = 'Direcciones más activas:';
$string['summaryline'] = '{$a->total} ataques vistos, {$a->blocked} bloqueados.';
$string['summarywhat'] = 'Qué:';
$string['taskcleanup'] = 'Draco Insomnis: quitar evidencias antiguas y bloqueos terminados';
$string['test'] = 'Probar el cortafuegos';
$string['testblocked'] = 'Funciona: se reconoció una inyección en la base de datos y se bloqueó (403).';
$string['testhelp'] = 'Envía al sitio una petición inofensiva con forma de ataque y te dice qué pasó. No se registra.';
$string['testlogged'] = 'Funciona: se reconoció una inyección en la base de datos. En «Solo registrar» se anota pero no se detiene; pasa a «Bloquear» cuando estés listo.';
$string['testnone'] = 'No se reconoció el ataque de prueba. Avisa a Draco Insomnis, por favor.';
$string['testoff'] = 'El cortafuegos está apagado: enciéndelo, guarda y vuelve a probar.';
$string['testunreachable'] = 'La prueba no ha podido llegar a la web desde el propio servidor (algunos alojamientos no lo permiten). El cortafuegos puede funcionar igual: mira los últimos intentos.';
$string['testupstream'] = 'La prueba se paró antes de llegar a Moodle, en el cortafuegos del propio alojamiento. Bien: dos capas.';
$string['trusted'] = 'Proxies de confianza';
$string['trusted_desc'] = 'Solo las conexiones desde estas direcciones pueden indicar la dirección del visitante con una cabecera. Una dirección o rango por línea. Vacío: este servidor y las redes privadas. Los rangos de Cloudflare ya los conoce el plugin.';
$string['unblock'] = 'Desbloquear';
$string['unblocked'] = 'Dirección desbloqueada.';
$string['waf'] = 'Cortafuegos';
$string['waf_desc'] = 'Para las peticiones con forma de ataque (inyección en la base de datos, lectura de archivos del servidor, ejecución de código, scripts en enlaces) y los escáneres como sqlmap o Nikto. Empieza con «Solo registrar» y pasa a «Bloquear» a los pocos días. Cinco ataques en 10 minutos bloquean la dirección una semana; las direcciones bloqueadas pueden seguir leyendo el sitio, pero no enviar nada ni iniciar sesión. Los administradores del sitio y los usuarios con «Saltarse el cortafuegos de Draco Insomnis» nunca se inspeccionan. Salida de emergencia: define(\'DRACO_WAF_OFF\', true); en config.php.';
$string['wafblock'] = 'Cortafuegos: {$a} ataques en 10 minutos';
$string['yourip'] = 'Tu dirección tal como la ve el plugin: <code>{$a->ip}</code> (dirección de la conexión: <code>{$a->remote}</code>). Si el sitio está detrás de Cloudflare u otro proxy y no coinciden con tu dirección real, elige la opción que corresponda en «IP del visitante».';
