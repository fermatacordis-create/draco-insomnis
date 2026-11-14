<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'pt_br' (generated from i18n/pt_BR.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Automático: {$a} tentativas de robô em 24 h';
$string['block'] = 'Bloquear';
$string['blockadd'] = 'Bloquear um endereço ou faixa';
$string['blockadd_desc'] = 'Nunca um administrador, nem o seu próprio endereço. Faixas não maiores que /16 (IPv4) ou /32 (IPv6).';
$string['blockdays'] = 'Por';
$string['blockdone'] = 'Bloqueado: {$a}';
$string['blockedtext'] = 'Esta requisição foi bloqueada por motivos de segurança. Se você acha que é um erro, entre em contato com o dono do site.';
$string['blockedtitle'] = 'Requisição bloqueada';
$string['blockrefused'] = 'Nada foi bloqueado: o valor não é válido, pertence a um administrador ou é o seu próprio endereço.';
$string['blocks'] = 'Endereços bloqueados';
$string['blockvalue'] = 'IP ou faixa (ex.: 203.0.113.0/24)';
$string['coldata'] = 'Dados';
$string['coldate'] = 'Data (UTC)';
$string['colemail'] = 'E-mail';
$string['colip'] = 'Endereço';
$string['colmessage'] = 'Mensagem';
$string['colreason'] = 'Motivo';
$string['colsigns'] = 'Sinais';
$string['coluntil'] = 'Até (UTC)';
$string['colvalue'] = 'Endereço ou e-mail';
$string['colverdict'] = 'Veredito';
$string['colwhere'] = 'Onde';
$string['days15'] = '15 dias';
$string['days30'] = '30 dias';
$string['days7'] = '7 dias';
$string['days90'] = '90 dias';
$string['done'] = 'Feito.';
$string['dracoinsomnis:bypassfirewall'] = 'Ignorar o firewall do Draco Insomnis';
$string['events'] = 'Últimas tentativas suspeitas';
$string['events_help'] = 'Guardadas por 90 dias. Nunca senhas. O CSV de um endereço tem tudo o que ele fez, pronto para anexar a uma denúncia de abuso ao provedor de rede dele.';
$string['evidence'] = 'Draco Insomnis: bloqueios e evidências';
$string['forever'] = 'Para sempre';
$string['geo'] = 'Países';
$string['geo_desc'] = 'Seus visitantes podem vir de muitos países, e um atacante troca de país com uma VPN. Filtre só login, cadastro e formulários, e comece com “Só registrar”. Administradores do site, pessoas que você liberou e buscadores nunca são filtrados. Precisa do firewall ligado (registrar ou bloquear).';
$string['geoaction'] = 'O que fazer';
$string['geocountries'] = 'Países (códigos de duas letras, ex.: ES, FR, DE)';
$string['geocredit'] = 'Geolocalização de IP por DB-IP (db-ip.com, CC BY 4.0), baixada quando você liga o filtro e consultada no seu próprio servidor: nenhum endereço é enviado a lugar nenhum.';
$string['geomode'] = 'Filtro';
$string['geoonly'] = 'Só os países da lista';
$string['georefuse'] = 'Recusar os países da lista';
$string['geoscope'] = 'Onde';
$string['geosensitive'] = 'Login, cadastros e formulários (recomendado)';
$string['geosite'] = 'O site inteiro';
$string['headers'] = 'Cabeçalhos de segurança';
$string['headers_desc'] = 'Nas páginas: sem adivinhar tipos de arquivo, sem exibição dentro de outros sites, menos dados de origem, sem câmera, microfone ou localização para conteúdo incorporado. Nunca um que o Moodle já envie.';
$string['hsts'] = 'Forçar HTTPS por 6 meses (HSTS)';
$string['hsts_desc'] = 'Só se o site inteiro funcionar em HTTPS e continuar assim: os navegadores guardam isso e recusam HTTP até expirar.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Barra cadastros falsos sem captchas: os robôs não ganham conta, e cada tentativa suspeita fica guardada 90 dias como prova para uma denúncia de abuso. Nada é enviado de volta ao atacante.</p><p>Endereços bloqueados e últimas tentativas: <a href="{$a}">Draco Insomnis: bloqueios e evidências</a>.</p>';
$string['modeblock'] = 'Bloquear';
$string['modelog'] = 'Só registrar: anotar o que barraria';
$string['modeoff'] = 'Desligado';
$string['nets'] = 'Redes de servidores alugados';
$string['nets_desc'] = 'Uma faixa por linha (CIDR), somada às que o plugin já conhece. Estar nesta lista só soma pontos: sozinha, nunca transforma ninguém em robô.';
$string['noblocks'] = 'Nada bloqueado agora.';
$string['noevents'] = 'Nada ainda.';
$string['noreviews'] = 'Nenhum pedido.';
$string['notdone'] = 'Não foi possível para esse endereço.';
$string['pace'] = 'Limite de ritmo anticópia';
$string['pace_desc'] = 'Quem pede mais páginas por minuto do que uma pessoa lê recebe “429 Too many requests” até o minuto acabar. Usuários logados, seus próprios endereços e buscadores verificados por DNS (Google, Bing, Apple, Yandex) nunca são limitados. Chamadas AJAX, serviços web e arquivos não contam.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Endereços e e-mails bloqueados por um tempo, pelo bloqueio automático ou por um administrador.';
$string['privacy:metadata:blocks:value'] = 'O endereço IP ou e-mail bloqueado.';
$string['privacy:metadata:events'] = 'Tentativas suspeitas (cadastros falsos, ataques, cópia em massa), guardadas 90 dias como prova para denúncias de abuso. Não ligadas a contas do Moodle. Nunca senhas.';
$string['privacy:metadata:events:fields'] = 'Nome de usuário, e-mail e página de origem enviados com a tentativa.';
$string['privacy:metadata:events:ip'] = 'O endereço IP de onde veio a tentativa.';
$string['privacy:metadata:events:timecreated'] = 'Quando a tentativa aconteceu.';
$string['privacy:metadata:events:useragent'] = 'O nome do navegador ou programa que ela enviou.';
$string['proxy'] = 'Endereço do visitante';
$string['proxy_desc'] = 'Deixe “Endereço da conexão” a menos que o site esteja atrás de um proxy: qualquer um pode forjar um cabeçalho.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'O cabeçalho é ignorado: esta conexão (<code>{$a}</code>) não vem do Cloudflare nem de um proxy confiável. Se o seu proxy está na internet, adicione os endereços dele em “Proxies confiáveis”.';
$string['proxynone'] = 'Endereço da conexão (recomendado)';
$string['proxyxff'] = 'Outro proxy (X-Forwarded-For)';
$string['pwdbreached'] = 'Recusar senhas encontradas em vazamentos de dados';
$string['pwdbreached_desc'] = 'Pergunta ao Have I Been Pwned com k-anonimato: só 5 caracteres do SHA-1 da senha saem do site, nunca a senha. Se o serviço não responder em 3 segundos, a senha é aceita. O Moodle aplica isso enquanto a “Política de senhas” estiver ligada (Administração do site > Segurança > Políticas de segurança do site).';
$string['pwdbreachedrefused'] = 'Esta senha aparece em vazamentos de dados conhecidos, então os atacantes a testam primeiro. Escolha outra, por favor.';
$string['pwdmin'] = 'Tamanho mínimo da senha';
$string['pwdmin_desc'] = 'De 8 a 64 caracteres; 0 deixa só a regra do próprio Moodle. Vale enquanto a “Política de senhas” estiver ligada.';
$string['pwdshort'] = 'A senha precisa ter pelo menos {$a} caracteres.';
$string['rateip'] = 'Páginas por minuto, por endereço';
$string['ratenet'] = 'Páginas por minuto, por rede';
$string['ratenet_desc'] = 'Uma rede /24 no IPv4 ou /64 no IPv6: o que um copiador consegue ao trocar por endereços vizinhos.';
$string['rejected'] = 'Não foi possível concluir o cadastro.';
$string['review1'] = 'Liberar por 24 horas';
$string['review30'] = '30 dias';
$string['review7'] = '7 dias';
$string['reviewapproved'] = 'Liberar';
$string['reviewattacker'] = 'Atacante: bloqueado';
$string['reviewattackerbtn'] = 'Atacante';
$string['reviewbody'] = 'Um visitante barrado pelo firewall pede uma revisão. Abra a página do Draco Insomnis para liberá-lo ou não.';
$string['reviewbutton'] = 'Pedir uma revisão';
$string['reviewdenied'] = 'Negado';
$string['reviewdeny'] = 'Negar';
$string['reviewemail'] = 'Seu e-mail';
$string['reviewmessage'] = 'O que você estava fazendo?';
$string['reviewreason'] = 'Revisão: {$a}';
$string['reviews'] = 'Pedidos de revisão';
$string['reviewsenttext'] = 'Obrigado. O responsável pelo site vai analisar e, se foi um erro, liberar você.';
$string['reviewsenttitle'] = 'Pedido enviado';
$string['reviewshelp'] = 'Quem foi barrado pelo firewall pode pedir pela página de bloqueio. Libere por um tempo se foi um erro. O Draco nunca escreve para a pessoa: responda pelo seu e-mail, se quiser.';
$string['reviewsubject'] = '[{$a}] Alguém pede que você revise um bloqueio do firewall';
$string['shield'] = 'Proteger o autocadastro';
$string['shield_desc'] = 'Adiciona uma armadilha invisível e um selo assinado da página ao formulário de cadastro (autocadastro por e-mail). Os robôs não ganham conta; três tentativas de robô em um dia bloqueiam o endereço por uma semana.';
$string['summary'] = 'Firewall: últimos 7 dias';
$string['summaryips'] = 'Endereços mais ativos:';
$string['summaryline'] = '{$a->total} ataques vistos, {$a->blocked} bloqueados.';
$string['summarywhat'] = 'O quê:';
$string['taskcleanup'] = 'Draco Insomnis: remover evidências antigas e bloqueios encerrados';
$string['test'] = 'Testar o firewall';
$string['testblocked'] = 'Funciona: uma injeção no banco de dados foi reconhecida e bloqueada (403).';
$string['testhelp'] = 'Envia ao site uma solicitação inofensiva com cara de ataque e diz o que aconteceu. Não é registrada.';
$string['testlogged'] = 'Funciona: uma injeção no banco de dados foi reconhecida. Em «Só registrar» ela é anotada mas não barrada; mude para «Bloquear» quando estiver pronto.';
$string['testnone'] = 'O ataque de teste não foi reconhecido. Por favor, avise a Draco Insomnis.';
$string['testoff'] = 'O firewall está desligado: ligue, salve e teste de novo.';
$string['testunreachable'] = 'O teste não conseguiu chegar ao site a partir do próprio servidor (algumas hospedagens não permitem). O firewall ainda pode estar funcionando: veja as últimas tentativas.';
$string['testupstream'] = 'O teste foi barrado antes de chegar ao Moodle, pelo firewall da própria hospedagem. Ótimo: duas camadas.';
$string['trusted'] = 'Proxies confiáveis';
$string['trusted_desc'] = 'Só conexões vindas destes endereços podem definir o endereço do visitante por um cabeçalho. Um endereço ou faixa por linha. Vazio: este servidor e as redes privadas. As faixas do próprio Cloudflare já são conhecidas.';
$string['unblock'] = 'Desbloquear';
$string['unblocked'] = 'Endereço desbloqueado.';
$string['waf'] = 'Firewall';
$string['waf_desc'] = 'Barra requisições com cara de ataque (injeção no banco de dados, leitura de arquivos do servidor, execução de código, scripts em links) e scanners como sqlmap ou Nikto. Comece com “Só registrar” e passe para “Bloquear” depois de alguns dias. Cinco ataques em 10 minutos bloqueiam o endereço por uma semana; endereços bloqueados ainda podem ler o site, mas não enviar nem fazer login. Administradores do site e usuários com “Ignorar o firewall do Draco Insomnis” nunca são inspecionados. Saída de emergência: define(\'DRACO_WAF_OFF\', true); em config.php.';
$string['wafblock'] = 'Firewall: {$a} ataques em 10 minutos';
$string['yourip'] = 'Seu endereço como o plugin o vê: <code>{$a->ip}</code> (endereço da conexão: <code>{$a->remote}</code>). Se o site estiver atrás do Cloudflare ou de outro proxy e eles forem diferentes do seu endereço real, escolha a opção correspondente em “Endereço do visitante”.';
