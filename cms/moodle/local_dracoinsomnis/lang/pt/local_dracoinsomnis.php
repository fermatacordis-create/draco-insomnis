<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'pt' (generated from i18n/pt_PT.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Automático: {$a} tentativas de robô em 24 h';
$string['block'] = 'Bloquear';
$string['blockadd'] = 'Bloquear um endereço ou intervalo';
$string['blockadd_desc'] = 'Nunca um administrador, nem o seu próprio endereço. Intervalos não mais largos do que /16 (IPv4) ou /32 (IPv6).';
$string['blockdays'] = 'Durante';
$string['blockdone'] = 'Bloqueado: {$a}';
$string['blockedtext'] = 'Este pedido foi travado por motivos de segurança. Se acha que se trata de um erro, contacte o proprietário do site.';
$string['blockedtitle'] = 'Pedido bloqueado';
$string['blockrefused'] = 'Nada foi bloqueado: o valor não é válido, pertence a um administrador ou é o seu próprio endereço.';
$string['blocks'] = 'Endereços bloqueados';
$string['blockvalue'] = 'IP ou intervalo (p. ex. 203.0.113.0/24)';
$string['coldata'] = 'Dados';
$string['coldate'] = 'Data (UTC)';
$string['colemail'] = 'E-mail';
$string['colip'] = 'Endereço';
$string['colmessage'] = 'Mensagem';
$string['colreason'] = 'Motivo';
$string['colsigns'] = 'Sinais';
$string['coluntil'] = 'Até (UTC)';
$string['colvalue'] = 'Endereço ou e-mail';
$string['colverdict'] = 'Veredicto';
$string['colwhere'] = 'Onde';
$string['days15'] = '15 dias';
$string['days30'] = '30 dias';
$string['days7'] = '7 dias';
$string['days90'] = '90 dias';
$string['done'] = 'Feito.';
$string['dracoinsomnis:bypassfirewall'] = 'Contornar a firewall do Draco Insomnis';
$string['events'] = 'Últimas tentativas suspeitas';
$string['events_help'] = 'Guardadas durante 90 dias. Nunca palavras-passe. O CSV de um endereço tem tudo o que ele fez, pronto a anexar a uma denúncia de abuso ao fornecedor de rede.';
$string['evidence'] = 'Draco Insomnis: bloqueios e provas';
$string['forever'] = 'Para sempre';
$string['geo'] = 'Países';
$string['geo_desc'] = 'Os seus visitantes podem vir de muitos países, e um atacante muda de país com uma VPN. Filtre apenas o início de sessão, o registo e os formulários, e comece com «Apenas registar». Administradores do site, pessoas que deixou passar e motores de pesquisa nunca são filtrados. Precisa da firewall ligada (registar ou bloquear).';
$string['geoaction'] = 'O que fazer';
$string['geocountries'] = 'Países (códigos de duas letras, p. ex. ES, FR, DE)';
$string['geocredit'] = 'Geolocalização de IP pela DB-IP (db-ip.com, CC BY 4.0), descarregada quando liga o filtro e consultada no seu próprio servidor: nenhum endereço é enviado para lado nenhum.';
$string['geomode'] = 'Filtro';
$string['geoonly'] = 'Só os países da lista';
$string['georefuse'] = 'Recusar os países da lista';
$string['geoscope'] = 'Onde';
$string['geosensitive'] = 'Acesso, registos e formulários (recomendado)';
$string['geosite'] = 'Todo o site';
$string['headers'] = 'Cabeçalhos de segurança';
$string['headers_desc'] = 'Nas páginas: sem adivinhar tipos de ficheiro, sem apresentação dentro de outros sites, menos dados de origem, sem câmara, microfone ou localização para conteúdo incorporado. Nunca um que o Moodle já envie.';
$string['hsts'] = 'Forçar HTTPS durante 6 meses (HSTS)';
$string['hsts_desc'] = 'Só se todo o site funcionar em HTTPS e continuar assim: os navegadores lembram-se e recusam HTTP até expirar.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Trava registos falsos sem captchas: os robôs não obtêm conta, e cada tentativa suspeita fica guardada 90 dias como prova para uma denúncia de abuso. Nunca é enviado nada de volta ao atacante.</p><p>Endereços bloqueados e últimas tentativas: <a href="{$a}">Draco Insomnis: bloqueios e provas</a>.</p>';
$string['modeblock'] = 'Bloquear';
$string['modelog'] = 'Apenas registar: anotar o que travaria';
$string['modeoff'] = 'Desligado';
$string['nets'] = 'Redes de servidores alugados';
$string['nets_desc'] = 'Um intervalo por linha (CIDR), somado aos que o plugin já conhece. Estar nesta lista só soma pontos: por si só, nunca faz de ninguém um robô.';
$string['noblocks'] = 'Nada bloqueado neste momento.';
$string['noevents'] = 'Ainda nada.';
$string['noreviews'] = 'Sem pedidos.';
$string['notdone'] = 'Não foi possível para esse endereço.';
$string['pace'] = 'Limite de ritmo anticópia';
$string['pace_desc'] = 'Quem pede mais páginas por minuto do que uma pessoa lê recebe «429 Too many requests» até o minuto acabar. Os utilizadores com sessão iniciada, os seus próprios endereços e os motores de pesquisa verificados por DNS (Google, Bing, Apple, Yandex) nunca são limitados. Chamadas AJAX, serviços web e ficheiros não contam.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Endereços e e-mails bloqueados durante algum tempo, pelo bloqueio automático ou por um administrador.';
$string['privacy:metadata:blocks:value'] = 'O endereço IP ou e-mail bloqueado.';
$string['privacy:metadata:events'] = 'Tentativas suspeitas (registos falsos, ataques, cópia em massa), guardadas 90 dias como prova para denúncias de abuso. Não associadas a contas do Moodle. Nunca palavras-passe.';
$string['privacy:metadata:events:fields'] = 'Nome de utilizador, e-mail e página de origem enviados com a tentativa.';
$string['privacy:metadata:events:ip'] = 'O endereço IP de onde veio a tentativa.';
$string['privacy:metadata:events:timecreated'] = 'Quando aconteceu a tentativa.';
$string['privacy:metadata:events:useragent'] = 'O nome do navegador ou programa que enviou.';
$string['proxy'] = 'Endereço do visitante';
$string['proxy_desc'] = 'Deixe «Endereço da ligação», a menos que o site esteja atrás de um proxy: qualquer pessoa pode falsificar um cabeçalho.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'O cabeçalho é ignorado: esta ligação (<code>{$a}</code>) não vem do Cloudflare nem de um proxy de confiança. Se o seu proxy estiver na internet, acrescente os endereços dele em «Proxies de confiança».';
$string['proxynone'] = 'Endereço da ligação (recomendado)';
$string['proxyxff'] = 'Outro proxy (X-Forwarded-For)';
$string['pwdbreached'] = 'Recusar palavras-passe encontradas em fugas de dados';
$string['pwdbreached_desc'] = 'Pergunta ao Have I Been Pwned com k-anonimato: só saem do site 5 caracteres do SHA-1 da palavra-passe, nunca a palavra-passe. Se o serviço não responder em 3 segundos, a palavra-passe é aceite. O Moodle aplica-o enquanto a «Política de senhas» estiver ativa (Administração do site > Segurança > Políticas de segurança do site).';
$string['pwdbreachedrefused'] = 'Esta palavra-passe aparece em fugas de dados conhecidas, por isso os atacantes experimentam-na primeiro. Escolha outra, por favor.';
$string['pwdmin'] = 'Comprimento mínimo da palavra-passe';
$string['pwdmin_desc'] = 'De 8 a 64 caracteres; 0 deixa só a regra do próprio Moodle. Aplica-se enquanto a «Política de senhas» estiver ativa.';
$string['pwdshort'] = 'A palavra-passe tem de ter pelo menos {$a} caracteres.';
$string['rateip'] = 'Páginas por minuto, por endereço';
$string['ratenet'] = 'Páginas por minuto, por rede';
$string['ratenet_desc'] = 'Uma rede /24 em IPv4 ou /64 em IPv6: o que um copiador obtém ao alternar entre endereços vizinhos.';
$string['rejected'] = 'Não foi possível concluir o registo.';
$string['review1'] = 'Deixar passar 24 horas';
$string['review30'] = '30 dias';
$string['review7'] = '7 dias';
$string['reviewapproved'] = 'Deixar passar';
$string['reviewattacker'] = 'Atacante: bloqueado';
$string['reviewattackerbtn'] = 'Atacante';
$string['reviewbody'] = 'Um visitante travado pela firewall pede uma revisão. Abra a página do Draco Insomnis para o deixar passar ou não.';
$string['reviewbutton'] = 'Pedir uma revisão';
$string['reviewdenied'] = 'Recusado';
$string['reviewdeny'] = 'Recusar';
$string['reviewemail'] = 'O seu e-mail';
$string['reviewmessage'] = 'O que estava a fazer?';
$string['reviewreason'] = 'Revisão: {$a}';
$string['reviews'] = 'Pedidos de revisão';
$string['reviewsenttext'] = 'Obrigado. O responsável do site vai analisar e, se foi um erro, deixá-lo passar.';
$string['reviewsenttitle'] = 'Pedido enviado';
$string['reviewshelp'] = 'Quem foi parado pela firewall pode pedir a partir da página de bloqueio. Deixe-o passar durante algum tempo se foi um erro. O Draco nunca lhe escreve: responda a partir do seu e-mail, se quiser.';
$string['reviewsubject'] = '[{$a}] Alguém pede-lhe que reveja um bloqueio da firewall';
$string['shield'] = 'Proteger o autorregisto';
$string['shield_desc'] = 'Acrescenta uma armadilha invisível e um selo assinado da página ao formulário de registo (autorregisto por e-mail). Os robôs não obtêm conta; três tentativas de robô num dia bloqueiam o endereço durante uma semana.';
$string['summary'] = 'Firewall: últimos 7 dias';
$string['summaryips'] = 'Endereços mais ativos:';
$string['summaryline'] = '{$a->total} ataques vistos, {$a->blocked} bloqueados.';
$string['summarywhat'] = 'O quê:';
$string['taskcleanup'] = 'Draco Insomnis: remover provas antigas e bloqueios terminados';
$string['test'] = 'Testar a firewall';
$string['testblocked'] = 'Funciona: uma injeção na base de dados foi reconhecida e bloqueada (403).';
$string['testhelp'] = 'Envia ao site um pedido inofensivo com forma de ataque e diz-lhe o que aconteceu. Não fica registado.';
$string['testlogged'] = 'Funciona: uma injeção na base de dados foi reconhecida. Em «Só registar» é anotada mas não parada; passe a «Bloquear» quando estiver pronto.';
$string['testnone'] = 'O ataque de teste não foi reconhecido. Por favor, avise a Draco Insomnis.';
$string['testoff'] = 'A firewall está desligada: ligue-a, guarde e teste de novo.';
$string['testunreachable'] = 'O teste não conseguiu chegar ao site a partir do próprio servidor (alguns alojamentos não o permitem). A firewall pode estar a funcionar na mesma: veja as últimas tentativas.';
$string['testupstream'] = 'O teste foi travado antes de chegar ao Moodle, pela firewall do próprio alojamento. Bom: duas camadas.';
$string['trusted'] = 'Proxies de confiança';
$string['trusted_desc'] = 'Só as ligações vindas destes endereços podem definir o endereço do visitante através de um cabeçalho. Um endereço ou intervalo por linha. Vazio: este servidor e as redes privadas. Os intervalos do próprio Cloudflare já são conhecidos.';
$string['unblock'] = 'Desbloquear';
$string['unblocked'] = 'Endereço desbloqueado.';
$string['waf'] = 'Firewall';
$string['waf_desc'] = 'Trava pedidos com forma de ataque (injeção na base de dados, leitura de ficheiros do servidor, execução de código, scripts em ligações) e scanners como o sqlmap ou o Nikto. Comece com «Apenas registar» e passe para «Bloquear» ao fim de alguns dias. Cinco ataques em 10 minutos bloqueiam o endereço durante uma semana; os endereços bloqueados continuam a poder ler o site, mas não a enviar nem a iniciar sessão. Os administradores do site e os utilizadores com «Contornar a firewall do Draco Insomnis» nunca são inspecionados. Saída de emergência: define(\'DRACO_WAF_OFF\', true); em config.php.';
$string['wafblock'] = 'Firewall: {$a} ataques em 10 minutos';
$string['yourip'] = 'O seu endereço tal como o plugin o vê: <code>{$a->ip}</code> (endereço da ligação: <code>{$a->remote}</code>). Se o site estiver atrás do Cloudflare ou de outro proxy e estes forem diferentes do seu endereço real, escolha a opção correspondente em «Endereço do visitante».';
