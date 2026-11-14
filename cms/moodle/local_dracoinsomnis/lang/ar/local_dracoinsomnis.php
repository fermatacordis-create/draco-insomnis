<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Strings for component 'local_dracoinsomnis', language 'ar' (generated from i18n/ar.json).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'تلقائي: {$a} محاولات روبوت في 24 ساعة';
$string['block'] = 'حظر';
$string['blockadd'] = 'حظر عنوان أو نطاق';
$string['blockadd_desc'] = 'لا يُحظر مسؤول ولا عنوانك أبدًا. النطاقات لا تتجاوز ‎/16 (IPv4) أو ‎/32 (IPv6).';
$string['blockdays'] = 'المدة';
$string['blockdone'] = 'محظور: {$a}';
$string['blockedtext'] = 'تم إيقاف هذا الطلب لأسباب أمنية. إذا كنت تعتقد أن هذا خطأ، فتواصل مع مالك الموقع.';
$string['blockedtitle'] = 'تم حظر الطلب';
$string['blockrefused'] = 'لم يُحظر شيء: القيمة غير صالحة، أو تخص مديرًا، أو هي عنوانك أنت.';
$string['blocks'] = 'العناوين المحظورة';
$string['blockvalue'] = 'عنوان IP أو نطاق (مثل 203.0.113.0/24)';
$string['coldata'] = 'بيانات';
$string['coldate'] = 'التاريخ (UTC)';
$string['colemail'] = 'البريد الإلكتروني';
$string['colip'] = 'العنوان';
$string['colmessage'] = 'الرسالة';
$string['colreason'] = 'السبب';
$string['colsigns'] = 'علامات';
$string['coluntil'] = 'حتى (UTC)';
$string['colvalue'] = 'العنوان أو البريد الإلكتروني';
$string['colverdict'] = 'الحكم';
$string['colwhere'] = 'أين';
$string['days15'] = '15 يومًا';
$string['days30'] = '30 يومًا';
$string['days7'] = '7 أيام';
$string['days90'] = '90 يومًا';
$string['done'] = 'تم.';
$string['dracoinsomnis:bypassfirewall'] = 'تجاوز جدار حماية Draco Insomnis';
$string['events'] = 'آخر المحاولات المشبوهة';
$string['events_help'] = 'تُحفظ 90 يومًا. لا كلمات مرور أبدًا. يحوي ملف CSV لكل عنوان كل ما فعله، جاهزًا لإرفاقه ببلاغ إساءة استخدام إلى مزوّد شبكته.';
$string['evidence'] = 'Draco Insomnis: الحظر والأدلة';
$string['forever'] = 'إلى الأبد';
$string['geo'] = 'البلدان';
$string['geo_desc'] = 'قد يأتي زوارك من بلدان كثيرة، والمهاجم يغيّر بلده عبر VPN. صفِّ تسجيل الدخول والتسجيل والنماذج فقط، وابدأ بـ«التسجيل فقط». لا يُصفّى أبدًا مسؤولو الموقع ولا من تسمح لهم بالمرور ولا محركات البحث. يحتاج إلى تشغيل جدار الحماية (تسجيل أو حظر).';
$string['geoaction'] = 'ماذا تفعل';
$string['geocountries'] = 'البلدان (رموز من حرفين، مثل ES وFR وDE)';
$string['geocredit'] = 'تحديد الموقع الجغرافي لعناوين IP من DB-IP (db-ip.com، CC BY 4.0)، يُنزَّل عند تشغيل المرشح ويُستعلم عنه على خادمك: لا يُرسل أي عنوان إلى أي مكان.';
$string['geomode'] = 'المرشح';
$string['geoonly'] = 'البلدان المدرجة فقط';
$string['georefuse'] = 'رفض البلدان المدرجة';
$string['geoscope'] = 'أين';
$string['geosensitive'] = 'تسجيل الدخول والتسجيل والنماذج (موصى به)';
$string['geosite'] = 'الموقع كله';
$string['headers'] = 'ترويسات الأمان';
$string['headers_desc'] = 'في الصفحات: لا تخمين لأنواع الملفات، ولا تضمين داخل مواقع أخرى، وبيانات أقل عن المصدر، ولا كاميرا أو ميكروفون أو موقع للمحتوى المضمّن. لا ترويسة يرسلها Moodle بالفعل أبدًا.';
$string['hsts'] = 'فرض HTTPS لمدة 6 أشهر (HSTS)';
$string['hsts_desc'] = 'فقط إن كان الموقع كله يعمل عبر HTTPS وسيبقى كذلك: تتذكر المتصفحات ذلك وترفض HTTP حتى ينتهي.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> يوقف التسجيلات المزيفة بلا كابتشا: لا تحصل الروبوتات على حساب، وتُحفظ كل محاولة مشبوهة 90 يومًا دليلًا لبلاغ عن إساءة الاستخدام. لا يُرسل أي شيء إلى المهاجم أبدًا.</p><p>العناوين المحظورة وآخر المحاولات: <a href="{$a}">Draco Insomnis: الحظر والأدلة</a>.</p>';
$string['modeblock'] = 'حظر';
$string['modelog'] = 'التسجيل فقط: تدوين ما كان سيُوقَف';
$string['modeoff'] = 'متوقف';
$string['nets'] = 'شبكات الخوادم المستأجرة';
$string['nets_desc'] = 'نطاق واحد في كل سطر (CIDR)، يُضاف إلى النطاقات التي تعرفها الإضافة. الوجود في هذه القائمة يضيف نقاطًا فقط: وحده لا يجعل أحدًا روبوتًا أبدًا.';
$string['noblocks'] = 'لا شيء محظور الآن.';
$string['noevents'] = 'لا شيء بعد.';
$string['noreviews'] = 'لا توجد طلبات.';
$string['notdone'] = 'تعذّر تنفيذ ذلك لهذا العنوان.';
$string['pace'] = 'حدّ سرعة التصفح ضد النسخ';
$string['pace_desc'] = 'من يطلب صفحات في الدقيقة أكثر مما يقرأ الإنسان يتلقى «429 Too many requests» حتى تنتهي الدقيقة. لا يُقيَّد أبدًا المستخدمون المسجلون دخولهم ولا عناوينك ولا محركات البحث الموثّقة عبر DNS (Google وBing وApple وYandex). لا تُحتسب طلبات AJAX وخدمات الويب والملفات.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'عناوين وبريد إلكتروني محظورة لفترة، بالحظر التلقائي أو من قِبل مسؤول.';
$string['privacy:metadata:blocks:value'] = 'عنوان IP أو البريد الإلكتروني المحظور.';
$string['privacy:metadata:events'] = 'محاولات مشبوهة (تسجيلات مزيفة، هجمات، نسخ جماعي)، تُحفظ 90 يومًا أدلةً لبلاغات إساءة الاستخدام. غير مرتبطة بحسابات Moodle. لا كلمات مرور أبدًا.';
$string['privacy:metadata:events:fields'] = 'اسم المستخدم والبريد الإلكتروني والصفحة المُحيلة المرسلة مع المحاولة.';
$string['privacy:metadata:events:ip'] = 'عنوان IP الذي جاءت منه المحاولة.';
$string['privacy:metadata:events:timecreated'] = 'وقت حدوث المحاولة.';
$string['privacy:metadata:events:useragent'] = 'اسم المتصفح أو البرنامج الذي أرسله.';
$string['proxy'] = 'عنوان الزائر';
$string['proxy_desc'] = 'اترك «عنوان الاتصال» ما لم يكن الموقع خلف وكيل: يمكن لأي أحد تزوير الترويسة.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'تُتجاهل الترويسة: هذا الاتصال (<code>{$a}</code>) لا يأتي من Cloudflare ولا من وكيل موثوق. إذا كان وكيلك على الإنترنت، فأضف عناوينه في «الوكلاء الموثوقون».';
$string['proxynone'] = 'عنوان الاتصال (موصى به)';
$string['proxyxff'] = 'وكيل آخر (X-Forwarded-For)';
$string['pwdbreached'] = 'رفض كلمات المرور الموجودة في تسريبات البيانات';
$string['pwdbreached_desc'] = 'يسأل Have I Been Pwned بإخفاء الهوية k: لا يغادر الموقع سوى 5 أحرف من SHA-1 لكلمة المرور، ولا تغادره كلمة المرور أبدًا. إذا لم تستجب الخدمة خلال 3 ثوانٍ، تُقبل كلمة المرور. يطبّقه Moodle ما دامت «سياسة كلمات المرور» مفعّلة (إدارة الموقع > الأمان > سياسات أمان الموقع).';
$string['pwdbreachedrefused'] = 'تظهر كلمة المرور هذه في تسريبات بيانات معروفة، لذلك يجربها المهاجمون أولًا. اختر كلمة أخرى من فضلك.';
$string['pwdmin'] = 'الحد الأدنى لطول كلمة المرور';
$string['pwdmin_desc'] = 'من 8 إلى 64 حرفًا؛ القيمة 0 تُبقي قاعدة Moodle وحدها. يُطبَّق ما دامت «سياسة كلمات المرور» مفعّلة.';
$string['pwdshort'] = 'يجب أن تتكون كلمة المرور من {$a} أحرف على الأقل.';
$string['rateip'] = 'صفحات في الدقيقة لكل عنوان';
$string['ratenet'] = 'صفحات في الدقيقة لكل شبكة';
$string['ratenet_desc'] = 'شبكة ‎/24 في IPv4 أو ‎/64 في IPv6: ما يحصل عليه برنامج النسخ حين يتنقل بين عناوين متجاورة.';
$string['rejected'] = 'تعذّر إكمال التسجيل.';
$string['review1'] = 'السماح بالمرور 24 ساعة';
$string['review30'] = '30 يومًا';
$string['review7'] = '7 أيام';
$string['reviewapproved'] = 'اسمح بالمرور';
$string['reviewattacker'] = 'مهاجم: محظور';
$string['reviewattackerbtn'] = 'مهاجم';
$string['reviewbody'] = 'زائر أوقفه جدار الحماية يطلب مراجعة. افتح صفحة Draco Insomnis للسماح له بالمرور أو لا.';
$string['reviewbutton'] = 'اطلب مراجعة';
$string['reviewdenied'] = 'مرفوض';
$string['reviewdeny'] = 'ارفض';
$string['reviewemail'] = 'بريدك الإلكتروني';
$string['reviewmessage'] = 'ماذا كنت تفعل؟';
$string['reviewreason'] = 'مراجعة: {$a}';
$string['reviews'] = 'طلبات المراجعة';
$string['reviewsenttext'] = 'شكرًا. سيراجعه مالك الموقع، وإن كان خطأً فسيسمح لك بالمرور.';
$string['reviewsenttitle'] = 'تم إرسال الطلب';
$string['reviewshelp'] = 'يمكن لمن أوقفهم الجدار الناري الطلب من صفحة الحظر. اسمح لهم بالمرور لفترة إن كان خطأً. لا يراسلهم Draco أبدًا: أجبهم من بريدك إن أردت.';
$string['reviewsubject'] = '[{$a}] شخص يطلب منك مراجعة حظر من جدار الحماية';
$string['shield'] = 'حماية التسجيل الذاتي';
$string['shield_desc'] = 'يضيف فخًا غير مرئي وختمًا موقّعًا للصفحة إلى نموذج التسجيل (التسجيل الذاتي عبر البريد الإلكتروني). لا تحصل الروبوتات على حساب؛ وثلاث محاولات روبوت في يوم واحد تحظر العنوان أسبوعًا.';
$string['summary'] = 'جدار الحماية: آخر 7 أيام';
$string['summaryips'] = 'أكثر العناوين نشاطًا:';
$string['summaryline'] = 'رُصدت {$a->total} هجمات، حُظرت {$a->blocked}.';
$string['summarywhat'] = 'ماذا:';
$string['taskcleanup'] = 'Draco Insomnis: حذف الأدلة القديمة وحالات الحظر المنتهية';
$string['test'] = 'اختبر الجدار الناري';
$string['testblocked'] = 'يعمل: تم التعرّف على حقن في قاعدة البيانات وحظره (403).';
$string['testhelp'] = 'يرسل إلى الموقع طلبًا غير ضار على شكل هجوم ويخبرك بما حدث. لا يُسجَّل.';
$string['testlogged'] = 'يعمل: تم التعرّف على حقن في قاعدة البيانات. في وضع «التسجيل فقط» يُدوَّن ولا يُوقف؛ انتقل إلى «حظر» عندما تكون جاهزًا.';
$string['testnone'] = 'لم يُتعرَّف على هجوم الاختبار. يُرجى إبلاغ Draco Insomnis.';
$string['testoff'] = 'الجدار الناري متوقف: شغّله واحفظ ثم اختبر مجددًا.';
$string['testunreachable'] = 'تعذّر على الاختبار الوصول إلى الموقع من الخادم نفسه (بعض الاستضافات لا تسمح بذلك). قد يعمل جدار الحماية مع ذلك: راجع آخر المحاولات.';
$string['testupstream'] = 'أُوقف الاختبار قبل وصوله إلى Moodle بجدار حماية الاستضافة نفسها. جيد: طبقتان.';
$string['trusted'] = 'الوكلاء الموثوقون';
$string['trusted_desc'] = 'لا يحق إلا للاتصالات القادمة من هذه العناوين تحديد عنوان الزائر عبر ترويسة. عنوان أو نطاق واحد في كل سطر. فارغ: هذا الخادم والشبكات الخاصة. نطاقات Cloudflare نفسها معروفة مسبقًا.';
$string['unblock'] = 'إلغاء الحظر';
$string['unblocked'] = 'أُلغي حظر العنوان.';
$string['waf'] = 'جدار الحماية';
$string['waf_desc'] = 'يوقف الطلبات التي تحمل شكل هجوم (حقن قاعدة البيانات، قراءة ملفات الخادم، تشغيل شيفرة، سكربتات في الروابط) والماسحات مثل sqlmap أو Nikto. ابدأ بـ«التسجيل فقط» وانتقل إلى «حظر» بعد بضعة أيام. خمس هجمات في 10 دقائق تحظر العنوان أسبوعًا؛ ويظل بإمكان العناوين المحظورة قراءة الموقع، لكن دون الإرسال أو تسجيل الدخول. لا يُفحص أبدًا مسؤولو الموقع ولا المستخدمون الذين لديهم «تجاوز جدار حماية Draco Insomnis». مخرج الطوارئ: define(\'DRACO_WAF_OFF\', true); في config.php.';
$string['wafblock'] = 'جدار الحماية: {$a} هجمات في 10 دقائق';
$string['yourip'] = 'عنوانك كما تراه الإضافة: <code>{$a->ip}</code> (عنوان الاتصال: <code>{$a->remote}</code>). إذا كان الموقع خلف Cloudflare أو وكيل آخر واختلف هذان عن عنوانك الحقيقي، فاختر الخيار المناسب في «عنوان الزائر».';
