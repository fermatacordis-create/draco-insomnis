<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'zh_cn' (generated from i18n/zh_CN.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = '自动：24 小时内 {$a} 次机器人尝试';
$string['block'] = '封锁';
$string['blockadd'] = '封锁一个地址或范围';
$string['blockadd_desc'] = '绝不封锁管理员，也不封锁你自己的地址。范围不得宽于 /16（IPv4）或 /32（IPv6）。';
$string['blockdays'] = '时长';
$string['blockdone'] = '已封锁：{$a}';
$string['blockedtext'] = '出于安全原因，此请求已被拦截。如果你认为这是误判，请联系网站所有者。';
$string['blockedtitle'] = '请求已被拦截';
$string['blockrefused'] = '未封锁任何内容：该值无效、属于管理员，或是你自己的地址。';
$string['blocks'] = '被封锁的地址';
$string['blockvalue'] = 'IP 或网段（例如 203.0.113.0/24）';
$string['coldata'] = '数据';
$string['coldate'] = '日期 (UTC)';
$string['colemail'] = '邮箱';
$string['colip'] = '地址';
$string['colmessage'] = '留言';
$string['colreason'] = '原因';
$string['colsigns'] = '迹象';
$string['coluntil'] = '截止 (UTC)';
$string['colvalue'] = '地址或电子邮件';
$string['colverdict'] = '判定';
$string['colwhere'] = '范围';
$string['days15'] = '15 天';
$string['days30'] = '30 天';
$string['days7'] = '7 天';
$string['days90'] = '90 天';
$string['done'] = '完成。';
$string['dracoinsomnis:bypassfirewall'] = '绕过 Draco Insomnis 防火墙';
$string['events'] = '最近的可疑尝试';
$string['events_help'] = '保存 90 天。绝不保存密码。某个地址的 CSV 包含它做过的一切，可以直接附在向其网络服务商提交的滥用举报中。';
$string['evidence'] = 'Draco Insomnis：封锁与证据';
$string['forever'] = '永久';
$string['geo'] = '国家';
$string['geo_desc'] = '你的访客可能来自许多国家，而攻击者会用 VPN 换国家。只过滤登录、注册和表单，并先用“仅记录”。网站管理员、你放行的人和搜索引擎永远不会被过滤。需要开启防火墙（记录或封锁）。';
$string['geoaction'] = '处理方式';
$string['geocountries'] = '国家（两字母代码，例如 ES, FR, DE）';
$string['geocredit'] = 'IP 地理定位由 DB-IP 提供（db-ip.com，CC BY 4.0），在你开启过滤时下载，并在你自己的服务器上查询：不会把任何地址发往别处。';
$string['geomode'] = '过滤';
$string['geoonly'] = '仅允许列表中的国家';
$string['georefuse'] = '拒绝列表中的国家';
$string['geoscope'] = '范围';
$string['geosensitive'] = '登录、注册和表单（推荐）';
$string['geosite'] = '整个网站';
$string['headers'] = '安全响应头';
$string['headers_desc'] = '在页面上：不猜测文件类型、不允许其他网站嵌入、减少来源信息、不为嵌入内容开放摄像头、麦克风或位置。绝不重复发送 Moodle 已发送的响应头。';
$string['hsts'] = '强制 HTTPS 6 个月（HSTS）';
$string['hsts_desc'] = '仅当整个网站都使用 HTTPS 且会一直如此时启用：浏览器会记住，在到期前拒绝 HTTP。';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> 无需验证码即可阻止虚假注册：机器人拿不到账户，每次可疑尝试都会保存 90 天，作为滥用举报的证据。绝不会向攻击者回发任何内容。</p><p>被封锁的地址和最近的尝试：<a href="{$a}">Draco Insomnis：封锁与证据</a>。</p>';
$string['modeblock'] = '封锁';
$string['modelog'] = '仅记录：记下本会阻止的内容';
$string['modeoff'] = '关闭';
$string['nets'] = '租用服务器网段';
$string['nets_desc'] = '每行一个范围（CIDR），会添加到插件已知的范围中。出现在此列表中只会加分：单凭它永远不会把任何人判定为机器人。';
$string['noblocks'] = '目前没有任何封锁。';
$string['noevents'] = '暂无记录。';
$string['noreviews'] = '暂无申请。';
$string['notdone'] = '无法对该地址执行此操作。';
$string['pace'] = '防复制速率限制';
$string['pace_desc'] = '每分钟请求的页面数超过一个人能阅读的数量时，会收到“429 Too many requests”，直到这一分钟结束。已登录用户、你自己的地址以及经 DNS 验证的搜索引擎（Google、Bing、Apple、Yandex）永远不受限制。AJAX 调用、Web 服务和文件不计入。';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = '由自动封锁或管理员暂时封锁的地址和电子邮件。';
$string['privacy:metadata:blocks:value'] = '被封锁的 IP 地址或电子邮件。';
$string['privacy:metadata:events'] = '可疑尝试（虚假注册、攻击、批量抓取），保存 90 天，作为滥用举报的证据。不与 Moodle 账户关联。绝不保存密码。';
$string['privacy:metadata:events:fields'] = '随尝试一起提交的用户名、电子邮件和来源页面。';
$string['privacy:metadata:events:ip'] = '尝试来源的 IP 地址。';
$string['privacy:metadata:events:timecreated'] = '尝试发生的时间。';
$string['privacy:metadata:events:useragent'] = '它发送的浏览器或程序名称。';
$string['proxy'] = '访客地址';
$string['proxy_desc'] = '除非网站位于代理之后，否则请保留“连接地址”：任何人都能伪造请求头。';
$string['proxycf'] = 'Cloudflare（CF-Connecting-IP）';
$string['proxyignored'] = '请求头被忽略：此连接（<code>{$a}</code>）既不是来自 Cloudflare，也不是来自受信任的代理。如果你的代理在互联网上，请在“受信任的代理”中添加它的地址。';
$string['proxynone'] = '连接地址（推荐）';
$string['proxyxff'] = '其他代理（X-Forwarded-For）';
$string['pwdbreached'] = '拒绝在数据泄露中出现过的密码';
$string['pwdbreached_desc'] = '以 k-匿名方式查询 Have I Been Pwned：只有密码 SHA-1 的前 5 个字符离开网站，绝不发送密码本身。如果服务在 3 秒内没有响应，则接受该密码。只要“密码规则”处于开启状态（网站管理 > 安全 > 网站安全设置），Moodle 就会应用它。';
$string['pwdbreachedrefused'] = '此密码出现在已知的数据泄露中，攻击者会最先尝试。请换一个。';
$string['pwdmin'] = '密码最小长度';
$string['pwdmin_desc'] = '8 到 64 个字符；0 表示只保留 Moodle 自己的规则。在“密码规则”开启时生效。';
$string['pwdshort'] = '密码至少需要 {$a} 个字符。';
$string['rateip'] = '每个地址每分钟的页面数';
$string['ratenet'] = '每个网段每分钟的页面数';
$string['ratenet_desc'] = 'IPv4 的 /24 网段或 IPv6 的 /64：抓取程序轮换相邻地址时能拿到的范围。';
$string['rejected'] = '无法完成注册。';
$string['review1'] = '放行 24 小时';
$string['review30'] = '30 天';
$string['review7'] = '7 天';
$string['reviewapproved'] = '放行';
$string['reviewattacker'] = '攻击者：已拦截';
$string['reviewattackerbtn'] = '攻击者';
$string['reviewbody'] = '一位被防火墙拦下的访客请求复核。打开 Draco Insomnis 页面决定是否放行。';
$string['reviewbutton'] = '申请复核';
$string['reviewdenied'] = '已拒绝';
$string['reviewdeny'] = '拒绝';
$string['reviewemail'] = '你的邮箱';
$string['reviewmessage'] = '你当时在做什么？';
$string['reviewreason'] = '复核：{$a}';
$string['reviews'] = '复核申请';
$string['reviewsenttext'] = '谢谢。网站负责人会查看，如果是误拦会放你通过。';
$string['reviewsenttitle'] = '申请已发送';
$string['reviewshelp'] = '被防火墙拦下的人可以在拦截页面申请。如果是误拦，可暂时放行。Draco 从不给他们写信：如有需要，请用你自己的邮箱回复。';
$string['reviewsubject'] = '[{$a}] 有人请你复核一次防火墙封锁';
$string['shield'] = '保护自助注册';
$string['shield_desc'] = '在注册表单中加入一个隐形陷阱和一个签名的页面戳（基于电子邮件的自助注册）。机器人拿不到账户；一天内三次机器人尝试会把该地址封锁一周。';
$string['summary'] = '防火墙：最近 7 天';
$string['summaryips'] = '最活跃的地址：';
$string['summaryline'] = '发现 {$a->total} 次攻击，封锁 {$a->blocked} 次。';
$string['summarywhat'] = '内容：';
$string['taskcleanup'] = 'Draco Insomnis：删除旧证据和已结束的封锁';
$string['test'] = '测试防火墙';
$string['testblocked'] = '正常：识别出数据库注入并已拦截（403）。';
$string['testhelp'] = '向网站发送一个无害的攻击样式请求，并告诉你结果。不会被记录。';
$string['testlogged'] = '正常：识别出数据库注入。在“仅记录”模式下只记录不拦截；准备好后切换到“拦截”。';
$string['testnone'] = '未能识别测试攻击。请向 Draco Insomnis 报告。';
$string['testoff'] = '防火墙已关闭：请开启并保存，然后再测试。';
$string['testunreachable'] = '测试无法从服务器本身访问网站（部分主机不允许这样做）。防火墙仍可能在工作：请查看最近的尝试。';
$string['testupstream'] = '测试在到达 Moodle 之前就被主机自己的防火墙拦下了。很好：两层防护。';
$string['trusted'] = '受信任的代理';
$string['trusted_desc'] = '只有来自这些地址的连接才能通过请求头设置访客地址。每行一个地址或范围。留空：本服务器和私有网络。Cloudflare 自己的范围已经内置。';
$string['unblock'] = '解除封锁';
$string['unblocked'] = '地址已解除封锁。';
$string['waf'] = '防火墙';
$string['waf_desc'] = '阻止具有攻击特征的请求（数据库注入、读取服务器文件、执行代码、链接中的脚本）以及 sqlmap、Nikto 等扫描器。先用“仅记录”，几天后再改为“封锁”。10 分钟内五次攻击会把该地址封锁一周；被封锁的地址仍可浏览网站，但不能提交或登录。网站管理员和拥有“绕过 Draco Insomnis 防火墙”权限的用户永远不会被检查。紧急出口：在 config.php 中写入 define(\'DRACO_WAF_OFF\', true);。';
$string['wafblock'] = '防火墙：10 分钟内 {$a} 次攻击';
$string['yourip'] = '插件看到的你的地址：<code>{$a->ip}</code>（连接地址：<code>{$a->remote}</code>）。如果网站位于 Cloudflare 或其他代理之后，且它们与你的真实地址不同，请在“访客地址”中选择相应选项。';
