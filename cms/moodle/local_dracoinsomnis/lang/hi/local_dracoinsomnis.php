<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'hi' (generated from i18n/hi.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'स्वचालित: 24 घंटे में {$a} बॉट प्रयास';
$string['block'] = 'ब्लॉक करें';
$string['blockadd'] = 'किसी पते या रेंज को ब्लॉक करें';
$string['blockadd_desc'] = 'कभी कोई एडमिन नहीं, न आपका अपना पता। रेंज /16 (IPv4) या /32 (IPv6) से चौड़ी नहीं।';
$string['blockdays'] = 'अवधि';
$string['blockdone'] = 'ब्लॉक किया गया: {$a}';
$string['blockedtext'] = 'यह अनुरोध सुरक्षा कारणों से रोका गया। अगर आपको लगता है कि यह ग़लती है, तो साइट के मालिक से संपर्क करें।';
$string['blockedtitle'] = 'अनुरोध रोका गया';
$string['blockrefused'] = 'कुछ भी ब्लॉक नहीं हुआ: मान अमान्य है, किसी व्यवस्थापक का है या आपका अपना पता है।';
$string['blocks'] = 'ब्लॉक किए गए पते';
$string['blockvalue'] = 'IP या रेंज (जैसे 203.0.113.0/24)';
$string['coldata'] = 'डेटा';
$string['coldate'] = 'तारीख़ (UTC)';
$string['colemail'] = 'ईमेल';
$string['colip'] = 'पता';
$string['colmessage'] = 'संदेश';
$string['colreason'] = 'कारण';
$string['colsigns'] = 'संकेत';
$string['coluntil'] = 'तक (UTC)';
$string['colvalue'] = 'पता या ईमेल';
$string['colverdict'] = 'निर्णय';
$string['colwhere'] = 'कहाँ';
$string['days15'] = '15 दिन';
$string['days30'] = '30 दिन';
$string['days7'] = '7 दिन';
$string['days90'] = '90 दिन';
$string['done'] = 'हो गया।';
$string['dracoinsomnis:bypassfirewall'] = 'Draco Insomnis फ़ायरवॉल को बायपास करें';
$string['events'] = 'हाल के संदिग्ध प्रयास';
$string['events_help'] = '90 दिन रखे जाते हैं। पासवर्ड कभी नहीं। किसी पते की CSV में उसका किया सब कुछ होता है, जो उसके नेटवर्क प्रदाता को दुरुपयोग की शिकायत के साथ लगाने के लिए तैयार है।';
$string['evidence'] = 'Draco Insomnis: ब्लॉक और सबूत';
$string['forever'] = 'हमेशा के लिए';
$string['geo'] = 'देश';
$string['geo_desc'] = 'आपके आगंतुक कई देशों से आ सकते हैं, और हमलावर VPN से देश बदल लेता है। केवल लॉग इन, पंजीकरण और फ़ॉर्म छानें, और “केवल दर्ज करें” से शुरू करें। साइट एडमिन, जिन्हें आप आने देते हैं वे लोग और सर्च इंजन कभी नहीं छाने जाते। फ़ायरवॉल चालू होना ज़रूरी है (दर्ज करें या ब्लॉक करें)।';
$string['geoaction'] = 'क्या करें';
$string['geocountries'] = 'देश (दो अक्षरों के कोड, जैसे ES, FR, DE)';
$string['geocredit'] = 'IP भू-स्थान DB-IP (db-ip.com, CC BY 4.0) से, जो फ़िल्टर चालू करने पर डाउनलोड होता है और आपके अपने सर्वर पर देखा जाता है: कोई भी पता कहीं नहीं भेजा जाता।';
$string['geomode'] = 'फ़िल्टर';
$string['geoonly'] = 'सिर्फ़ सूची वाले देश';
$string['georefuse'] = 'सूची वाले देशों को मना करें';
$string['geoscope'] = 'कहाँ';
$string['geosensitive'] = 'लॉगिन, साइन-अप और फ़ॉर्म (सुझाया गया)';
$string['geosite'] = 'पूरी साइट';
$string['headers'] = 'सुरक्षा हेडर';
$string['headers_desc'] = 'पेजों पर: फ़ाइल के प्रकार का अनुमान नहीं, दूसरी साइटों में जोड़ना नहीं, कम रेफ़रर डेटा, जुड़ी सामग्री के लिए कैमरा, माइक्रोफ़ोन या स्थान नहीं। Moodle का पहले से भेजा हेडर कभी दोबारा नहीं।';
$string['hsts'] = '6 महीने के लिए HTTPS अनिवार्य करें (HSTS)';
$string['hsts_desc'] = 'सिर्फ़ तभी जब पूरी साइट HTTPS पर चलती है और चलती रहेगी: ब्राउज़र इसे याद रखते हैं और समय खत्म होने तक HTTP को मना करते हैं।';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> कैप्चा के बिना नकली पंजीकरण रोकता है: बॉट को खाता नहीं मिलता, और हर संदिग्ध प्रयास दुरुपयोग की शिकायत के सबूत के रूप में 90 दिन रखा जाता है। हमलावर को कभी कुछ वापस नहीं भेजा जाता।</p><p>ब्लॉक किए गए पते और हाल के प्रयास: <a href="{$a}">Draco Insomnis: ब्लॉक और सबूत</a>।</p>';
$string['modeblock'] = 'ब्लॉक करें';
$string['modelog'] = 'केवल दर्ज करें: जो रोका जाता उसे लिखें';
$string['modeoff'] = 'बंद';
$string['nets'] = 'किराये के सर्वरों के नेटवर्क';
$string['nets_desc'] = 'हर पंक्ति में एक रेंज (CIDR), जो प्लगइन की पहले से जानी रेंजों में जुड़ती है। इस सूची में होना केवल अंक जोड़ता है: अकेले यह किसी को बॉट नहीं बनाता।';
$string['noblocks'] = 'अभी कुछ भी ब्लॉक नहीं है।';
$string['noevents'] = 'अभी कुछ नहीं।';
$string['noreviews'] = 'कोई अनुरोध नहीं।';
$string['notdone'] = 'उस पते के लिए यह नहीं हो सका।';
$string['pace'] = 'नकल-रोधी गति सीमा';
$string['pace_desc'] = 'जो एक मिनट में किसी इंसान के पढ़ने से ज़्यादा पेज माँगता है, उसे मिनट ख़त्म होने तक “429 Too many requests” मिलता है। लॉग इन किए उपयोगकर्ता, आपके अपने पते और DNS से सत्यापित सर्च इंजन (Google, Bing, Apple, Yandex) कभी सीमित नहीं होते। AJAX कॉल, वेब सेवाएँ और फ़ाइलें नहीं गिनी जातीं।';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'स्वचालित ब्लॉक या किसी एडमिन द्वारा कुछ समय के लिए ब्लॉक किए गए पते और ईमेल।';
$string['privacy:metadata:blocks:value'] = 'ब्लॉक किया गया IP पता या ईमेल।';
$string['privacy:metadata:events'] = 'संदिग्ध प्रयास (नकली पंजीकरण, हमले, बड़े पैमाने पर नकल), दुरुपयोग की शिकायतों के सबूत के रूप में 90 दिन रखे जाते हैं। Moodle खातों से जुड़े नहीं। पासवर्ड कभी नहीं।';
$string['privacy:metadata:events:fields'] = 'प्रयास के साथ भेजा गया उपयोगकर्ता नाम, ईमेल और रेफ़र करने वाला पेज।';
$string['privacy:metadata:events:ip'] = 'वह IP पता जहाँ से प्रयास आया।';
$string['privacy:metadata:events:timecreated'] = 'प्रयास कब हुआ।';
$string['privacy:metadata:events:useragent'] = 'उसके भेजे ब्राउज़र या प्रोग्राम का नाम।';
$string['proxy'] = 'आगंतुक का पता';
$string['proxy_desc'] = 'जब तक साइट किसी प्रॉक्सी के पीछे न हो, “कनेक्शन का पता” ही रहने दें: हेडर कोई भी जाली बना सकता है।';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'हेडर को अनदेखा किया जा रहा है: यह कनेक्शन (<code>{$a}</code>) न Cloudflare से आया है, न किसी भरोसेमंद प्रॉक्सी से। अगर आपका प्रॉक्सी इंटरनेट पर है, तो उसके पते “भरोसेमंद प्रॉक्सी” में जोड़ें।';
$string['proxynone'] = 'कनेक्शन का पता (अनुशंसित)';
$string['proxyxff'] = 'दूसरा प्रॉक्सी (X-Forwarded-For)';
$string['pwdbreached'] = 'डेटा लीक में मिले पासवर्ड अस्वीकार करें';
$string['pwdbreached_desc'] = 'k-अनामता के साथ Have I Been Pwned से पूछता है: साइट से पासवर्ड के SHA-1 के केवल 5 अक्षर बाहर जाते हैं, पासवर्ड कभी नहीं। अगर सेवा 3 सेकंड में जवाब न दे, तो पासवर्ड स्वीकार कर लिया जाता है। Moodle इसे तब तक लागू करता है जब तक “पासवर्ड नीति” चालू है (साइट प्रशासन > सुरक्षा > साइट सुरक्षा सेटिंग्स)।';
$string['pwdbreachedrefused'] = 'यह पासवर्ड जाने-माने डेटा लीक में मिलता है, इसलिए हमलावर इसे सबसे पहले आज़माते हैं। कृपया कोई दूसरा चुनें।';
$string['pwdmin'] = 'पासवर्ड की न्यूनतम लंबाई';
$string['pwdmin_desc'] = '8 से 64 अक्षर; 0 रखने पर केवल Moodle का अपना नियम रहता है। “पासवर्ड नीति” चालू रहने तक लागू।';
$string['pwdshort'] = 'पासवर्ड में कम से कम {$a} अक्षर होने चाहिए।';
$string['rateip'] = 'हर पते से प्रति मिनट पेज';
$string['ratenet'] = 'हर नेटवर्क से प्रति मिनट पेज';
$string['ratenet_desc'] = 'IPv4 के लिए /24 या IPv6 के लिए /64 नेटवर्क: पास-पास के पते बदलते रहने वाले स्क्रेपर को इतना ही मिलता है।';
$string['rejected'] = 'पंजीकरण पूरा नहीं हो सका।';
$string['review1'] = '24 घंटे आने दें';
$string['review30'] = '30 दिन';
$string['review7'] = '7 दिन';
$string['reviewapproved'] = 'जाने दें';
$string['reviewattacker'] = 'हमलावर: ब्लॉक किया गया';
$string['reviewattackerbtn'] = 'हमलावर';
$string['reviewbody'] = 'फ़ायरवॉल से रोका गया एक आगंतुक समीक्षा माँग रहा है। उसे आने देना है या नहीं, यह तय करने के लिए Draco Insomnis पेज खोलें।';
$string['reviewbutton'] = 'समीक्षा माँगें';
$string['reviewdenied'] = 'अस्वीकृत';
$string['reviewdeny'] = 'अस्वीकार करें';
$string['reviewemail'] = 'आपका ईमेल';
$string['reviewmessage'] = 'आप क्या कर रहे थे?';
$string['reviewreason'] = 'समीक्षा: {$a}';
$string['reviews'] = 'समीक्षा अनुरोध';
$string['reviewsenttext'] = 'धन्यवाद। साइट के मालिक इसे देखेंगे और, अगर यह गलती थी, तो आपको जाने देंगे।';
$string['reviewsenttitle'] = 'अनुरोध भेजा गया';
$string['reviewshelp'] = 'फ़ायरवॉल द्वारा रोके गए लोग ब्लॉक पेज से अनुरोध कर सकते हैं। अगर गलती थी तो उन्हें कुछ समय के लिए जाने दें। Draco उन्हें कभी नहीं लिखता: चाहें तो अपने ईमेल से जवाब दें।';
$string['reviewsubject'] = '[{$a}] कोई आपसे फ़ायरवॉल के एक ब्लॉक की समीक्षा करने को कह रहा है';
$string['shield'] = 'स्वयं-पंजीकरण सुरक्षित करें';
$string['shield_desc'] = 'पंजीकरण फ़ॉर्म (ईमेल से स्वयं-पंजीकरण) में एक अदृश्य जाल और पेज की हस्ताक्षरित मुहर जोड़ता है। बॉट को खाता नहीं मिलता; एक दिन में तीन बॉट प्रयास उस पते को एक हफ़्ते के लिए ब्लॉक कर देते हैं।';
$string['summary'] = 'फ़ायरवॉल: पिछले 7 दिन';
$string['summaryips'] = 'सबसे सक्रिय पते:';
$string['summaryline'] = '{$a->total} हमले दिखे, {$a->blocked} ब्लॉक किए गए।';
$string['summarywhat'] = 'क्या:';
$string['taskcleanup'] = 'Draco Insomnis: पुराने सबूत और ख़त्म हुए ब्लॉक हटाएँ';
$string['test'] = 'फ़ायरवॉल जाँचें';
$string['testblocked'] = 'काम करता है: डेटाबेस इंजेक्शन पहचाना गया और ब्लॉक किया गया (403)।';
$string['testhelp'] = 'साइट को हमले जैसा दिखने वाला एक हानिरहित अनुरोध भेजता है और बताता है कि क्या हुआ। यह दर्ज नहीं होता।';
$string['testlogged'] = 'काम करता है: डेटाबेस इंजेक्शन पहचाना गया। «केवल लॉग» में यह दर्ज होता है पर रोका नहीं जाता; तैयार होने पर «ब्लॉक करें» चुनें।';
$string['testnone'] = 'जाँच वाला हमला पहचाना नहीं गया। कृपया Draco Insomnis को बताएँ।';
$string['testoff'] = 'फ़ायरवॉल बंद है: इसे चालू करें, सहेजें और फिर से जाँचें।';
$string['testunreachable'] = 'परीक्षण सर्वर से ही साइट तक नहीं पहुँच सका (कुछ होस्टिंग इसकी अनुमति नहीं देतीं)। फ़ायरवॉल फिर भी काम कर रहा हो सकता है: हाल के प्रयास देखें।';
$string['testupstream'] = 'परीक्षण Moodle तक पहुँचने से पहले होस्टिंग के अपने फ़ायरवॉल ने रोक दिया। अच्छा: दो परतें।';
$string['trusted'] = 'भरोसेमंद प्रॉक्सी';
$string['trusted_desc'] = 'केवल इन पतों से आने वाले कनेक्शन हेडर के ज़रिए आगंतुक का पता तय कर सकते हैं। हर पंक्ति में एक पता या रेंज। ख़ाली: यह सर्वर और निजी नेटवर्क। Cloudflare की अपनी रेंज पहले से ज्ञात हैं।';
$string['unblock'] = 'अनब्लॉक करें';
$string['unblocked'] = 'पते से ब्लॉक हटा दिया गया।';
$string['waf'] = 'फ़ायरवॉल';
$string['waf_desc'] = 'हमले जैसे दिखने वाले अनुरोध (डेटाबेस इंजेक्शन, सर्वर की फ़ाइलें पढ़ना, कोड चलाना, लिंक में स्क्रिप्ट) और sqlmap या Nikto जैसे स्कैनर रोकता है। “केवल दर्ज करें” से शुरू करें और कुछ दिनों बाद “ब्लॉक करें” पर जाएँ। 10 मिनट में पाँच हमले उस पते को एक हफ़्ते के लिए ब्लॉक कर देते हैं; ब्लॉक किए गए पते साइट पढ़ सकते हैं, पर कुछ भेज या लॉग इन नहीं कर सकते। साइट एडमिन और “Draco Insomnis फ़ायरवॉल को बायपास करें” वाले उपयोगकर्ताओं की कभी जाँच नहीं होती। आपातकालीन रास्ता: config.php में define(\'DRACO_WAF_OFF\', true); लिखें।';
$string['wafblock'] = 'फ़ायरवॉल: 10 मिनट में {$a} हमले';
$string['yourip'] = 'प्लगइन को दिखने वाला आपका पता: <code>{$a->ip}</code> (कनेक्शन का पता: <code>{$a->remote}</code>)। अगर साइट Cloudflare या किसी दूसरे प्रॉक्सी के पीछे है और ये आपके असली पते से अलग हैं, तो “आगंतुक का पता” में सही विकल्प चुनें।';
