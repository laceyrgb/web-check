import { createPublicKey } from 'node:crypto';

import { registrableDomain } from '../domain.js';
import { clip, finding } from '../findings.js';
import { REFS } from '../refs.js';

const noAction = {
  remediation: 'No action needed.',
  remediationAr: 'لا يلزم إجراء.',
};

const tagsOf = (record) =>
  Object.fromEntries(
    String(record)
      .split(';')
      .map((part) => {
        const [tag, ...rest] = part.split('=');
        return [tag.trim().toLowerCase(), rest.join('=').trim()];
      })
      .filter(([tag]) => tag),
  );

const recordsAt = (txt, name) => {
  const rows = txt?.[name] || txt?.[name.toLowerCase()] || [];
  return (Array.isArray(rows) ? rows : [rows]).map((row) => String(row)).filter(Boolean);
};

const withPrefix = (rows, prefix) => rows.filter((row) => row.toLowerCase().startsWith(prefix));

const LOOKUP = /^(?:\+|-|~|\?)?(include|a|mx|ptr|exists|redirect)(?:[:/=]|$)/i;

const lookupCount = (record) =>
  record
    .trim()
    .split(/\s+/)
    .filter((term) => LOOKUP.test(term)).length;

const allQualifier = (record) => {
  const term = record
    .trim()
    .split(/\s+/)
    .find((part) => /^(?:\+|-|~|\?)?all$/i.test(part));
  if (!term) return null;
  if (
    term.startsWith('-') ||
    term.startsWith('~') ||
    term.startsWith('?') ||
    term.startsWith('+')
  ) {
    return term[0];
  }
  return '+';
};

const hasRedirect = (record) =>
  record
    .trim()
    .split(/\s+/)
    .some((term) => /^(?:\+|-|~|\?)?redirect=/i.test(term));

const isNullMx = (mx) =>
  Array.isArray(mx) &&
  mx.length > 0 &&
  mx.every((row) => {
    const exchange = String(row.exchange || '').replace(/\.$/, '');
    return exchange === '' || exchange === '.';
  });

// RSA bits from a DKIM p= value. Null means the key is not an RSA SPKI key.
const bitsOf = (b64) => {
  if (!b64) return null;
  try {
    const der = Buffer.from(b64, 'base64');
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
    return key.asymmetricKeyDetails?.modulusLength ?? null;
  } catch {
    return null;
  }
};

const dkimFromTxt = (txt, domain) => {
  const suffix = `._domainkey.${domain}`;
  const keys = [];
  for (const [name, rows] of Object.entries(txt || {})) {
    if (!name.toLowerCase().endsWith(suffix)) continue;
    const selector = name.slice(0, name.length - suffix.length).replace(/\.$/, '');
    for (const row of rows) {
      const tags = tagsOf(row);
      if (tags.v && tags.v.toLowerCase() !== 'dkim1') continue;
      keys.push({
        selector: selector || 'unknown',
        record: row,
        bits: bitsOf(tags.p),
        revoked: tags.p === '',
      });
    }
  }
  return keys;
};

const open = (spec) => finding({ status: 'open', ...spec });
const pass = (spec) => finding({ status: 'pass', severity: 'info', ...noAction, ...spec });

export const analyseEmail = (hostname, dns) => {
  if (!dns) return [];
  if (dns.error) {
    return [
      open({
        id: 'email.lookup-failed',
        title: 'Mail records could not be read',
        titleAr: 'تعذرت قراءة سجلات البريد',
        severity: 'info',
        evidence: clip(dns.error),
        remediation:
          'Repeat the DNS lookup. Do not treat a resolver failure as a missing SPF or DMARC record.',
        remediationAr: 'أعد استعلام DNS. لا تعامل فشل المحلل كغياب لسجل SPF أو DMARC.',
        references: [REFS.spf],
        service: 'email-domain',
      }),
    ];
  }
  const domain = hostname.toLowerCase();
  const org = registrableDomain(domain);
  const txt = dns.txt || {};
  const spf = withPrefix(recordsAt(txt, domain), 'v=spf1');
  const ownDmarc = withPrefix(recordsAt(txt, `_dmarc.${domain}`), 'v=dmarc1');
  const orgDmarc = org === domain ? [] : withPrefix(recordsAt(txt, `_dmarc.${org}`), 'v=dmarc1');
  const dmarc = ownDmarc.length ? ownDmarc : orgDmarc;
  const dmarcFrom = ownDmarc.length || org === domain ? domain : org;
  const bimi = withPrefix(recordsAt(txt, `default._bimi.${domain}`), 'v=bimi1');
  const tlsRpt = withPrefix(recordsAt(txt, `_smtp._tls.${domain}`), 'v=tlsrptv1');
  const mtaDns = withPrefix(recordsAt(txt, `_mta-sts.${domain}`), 'v=stsv1');
  const mx = Array.isArray(dns.mx) ? dns.mx : [];
  const nullMx = isNullMx(mx);
  const keys =
    Array.isArray(dns.dkim) && dns.dkim.length
      ? dns.dkim.map(normaliseKey)
      : dkimFromTxt(txt, domain);
  const lookedForDkim =
    Array.isArray(dns.dkim) || Object.keys(txt).some((name) => name.includes('._domainkey.'));

  return [
    checkSpf(spf, nullMx),
    checkDmarc(dmarc, dmarcFrom),
    checkDmarcSubdomains(dmarc),
    checkDkim(keys, nullMx, lookedForDkim),
    checkMtaSts(mtaDns, dns.mtaSts, mx, nullMx),
    checkTlsRpt(tlsRpt, mtaDns, dns.mtaSts),
    checkBimi(bimi, dmarc),
    checkNullMx(nullMx),
    ...checkDane(dns.dane),
  ].filter(Boolean);
};

const normaliseKey = (key) => ({
  selector: key.selector || 'unknown',
  bits: key.bits ?? bitsOf(tagsOf(key.record || '').p),
  revoked: key.revoked || tagsOf(key.record || '').p === '',
  record: key.record || '',
});

const checkSpf = (spf, nullMx) => {
  if (!spf.length) {
    return open({
      id: 'email.spf.missing',
      title: nullMx ? 'Null MX without an SPF record that rejects all mail' : 'No SPF record',
      titleAr: nullMx ? 'نطاق بلا بريد وارد وبدون SPF يرفض كل الإرسال' : 'لا يوجد سجل SPF',
      severity: nullMx ? 'medium' : 'high',
      evidence: `No v=spf1 TXT record at this name.`,
      remediation:
        'Publish one TXT record: v=spf1 listing the servers allowed to send, ending in -all. If the domain sends no mail, publish v=spf1 -all.',
      remediationAr:
        'انشر سجل TXT واحدًا يبدأ بـ v=spf1 ويسرد الخوادم المسموح لها بالإرسال وينتهي بـ -all. إذا كان النطاق لا يرسل بريدًا، انشر v=spf1 -all.',
      references: [REFS.spf],
      service: 'email-domain',
    });
  }
  if (spf.length > 1) {
    return open({
      id: 'email.spf.multiple',
      title: 'Multiple SPF records',
      titleAr: 'أكثر من سجل SPF',
      severity: 'high',
      evidence: `${spf.length} TXT records start with v=spf1. Receivers treat that as an error.`,
      remediation: 'Merge them into a single v=spf1 record.',
      remediationAr: 'ادمجها في سجل v=spf1 واحد.',
      references: [REFS.spf],
      service: 'email-domain',
    });
  }
  const record = spf[0];
  const lookups = lookupCount(record);
  if (lookups > 10) {
    return open({
      id: 'email.spf.lookups',
      title: 'SPF record asks for more than 10 DNS lookups',
      titleAr: 'سجل SPF يطلب أكثر من 10 عمليات بحث DNS',
      severity: 'high',
      evidence: `${lookups} lookup mechanisms on the first record, before nested includes: ${clip(record)}`,
      remediation:
        'Remove unused include: mechanisms or replace them with ip4/ip6 ranges so receivers do not hit the limit of 10.',
      remediationAr:
        'احذف آليات include غير المستخدمة أو استبدلها بنطاقات ip4/ip6 حتى لا يبلغ المستلم حد العشرة.',
      references: [REFS.spf],
      service: 'email-domain',
    });
  }
  const qualifier = allQualifier(record);
  if (qualifier === '+' || (qualifier == null && !hasRedirect(record))) {
    const plus = qualifier === '+';
    return open({
      id: plus ? 'email.spf.plus-all' : 'email.spf.no-all',
      title: plus
        ? 'SPF authorises every host on the internet'
        : 'SPF does not say what happens to other senders',
      titleAr: plus
        ? 'سجل SPF يسمح لأي مضيف على الإنترنت بالإرسال'
        : 'سجل SPF لا يحدد مصير المرسلين غير المذكورين',
      severity: plus ? 'high' : 'medium',
      evidence: clip(record),
      remediation: plus
        ? 'Replace +all with -all (or ~all while you are testing). +all lets anyone spoof this domain.'
        : 'End the record with -all, or ~all while you confirm legitimate mail still passes.',
      remediationAr: plus
        ? 'استبدل +all بـ -all (أو ~all أثناء الاختبار). +all يسمح لأي طرف بانتحال هذا النطاق.'
        : 'أنهِ السجل بـ -all، أو بـ ~all مؤقتًا حتى تتأكد أن البريد الشرعي ما زال يمر.',
      references: [REFS.spf],
      service: 'email-domain',
    });
  }
  if (qualifier === '?') {
    return open({
      id: 'email.spf.neutral',
      title: 'SPF is neutral about unlisted senders',
      titleAr: 'سياسة SPF محايدة تجاه المرسلين غير المذكورين',
      severity: 'medium',
      evidence: clip(record),
      remediation: 'Replace ?all with -all once legitimate senders are listed.',
      remediationAr: 'استبدل ?all بـ -all بعد إدراج المرسلين الشرعيين.',
      references: [REFS.spf],
      service: 'email-domain',
    });
  }
  if (qualifier === '~') {
    return open({
      id: 'email.spf.softfail',
      title: 'SPF soft-fails unlisted senders',
      titleAr: 'سجل SPF يكتفي بفشل مرن للمرسلين غير المذكورين',
      severity: 'low',
      evidence: clip(record),
      remediation:
        'Move from ~all to -all when aggregate DMARC reports show your own mail passing.',
      remediationAr: 'انتقل من ~all إلى -all عندما تُظهر تقارير DMARC أن بريدك الشرعي يجتاز الفحص.',
      references: [REFS.spf],
      service: 'email-domain',
    });
  }
  return pass({
    id: 'email.spf.pass',
    title: 'SPF record rejects or redirects unlisted senders',
    titleAr: 'سجل SPF يرفض المرسلين غير المذكورين أو يحيل إليهم',
    evidence: clip(record),
    references: [REFS.spf],
    service: 'email-domain',
  });
};

const enforced = (policy) => ['quarantine', 'reject'].includes(String(policy || '').toLowerCase());

const checkDmarc = (dmarc, from) => {
  if (!dmarc.length) {
    return open({
      id: 'email.dmarc.missing',
      title: 'No DMARC record',
      titleAr: 'لا يوجد سجل DMARC',
      severity: 'high',
      evidence: `No v=DMARC1 TXT record at _dmarc.${from}.`,
      remediation:
        'Publish one TXT record at the _dmarc name with v=DMARC1, p=quarantine or p=reject, and rua=mailto: so you receive aggregate reports.',
      remediationAr:
        'انشر سجل TXT واحدًا على اسم _dmarc بالقيمة v=DMARC1 والسياسة p=quarantine أو p=reject، مع rua=mailto: لاستلام التقارير المجمّعة.',
      references: [REFS.dmarc],
      service: 'email-domain',
    });
  }
  if (dmarc.length > 1) {
    return open({
      id: 'email.dmarc.multiple',
      title: 'Multiple DMARC records',
      titleAr: 'أكثر من سجل DMARC',
      severity: 'high',
      evidence: `${dmarc.length} records at _dmarc.${from}. Receivers ignore DMARC in that case.`,
      remediation: 'Leave a single DMARC TXT record.',
      remediationAr: 'أبقِ سجل DMARC نصيًا واحدًا فقط.',
      references: [REFS.dmarc],
      service: 'email-domain',
    });
  }
  const tags = tagsOf(dmarc[0]);
  const policy = (tags.p || '').toLowerCase();
  const percent = tags.pct === undefined || tags.pct === '' ? 100 : Number(tags.pct);
  if (!enforced(policy)) {
    return open({
      id: 'email.dmarc.monitor',
      title: 'DMARC is monitor-only',
      titleAr: 'سياسة DMARC للمراقبة فقط',
      severity: 'medium',
      evidence: `p=${policy || '(missing)'} at _dmarc.${from}. ${clip(dmarc[0])}`,
      remediation: tags.rua
        ? 'When reports show legitimate mail passing, change p= to quarantine and then reject.'
        : 'Add rua=mailto: first so you can see failures, then move p= to quarantine and then reject.',
      remediationAr: tags.rua
        ? 'عندما تُظهر التقارير أن البريد الشرعي يمر، غيّر p= إلى quarantine ثم إلى reject.'
        : 'أضف rua=mailto: أولًا لرؤية حالات الفشل، ثم انقل p= إلى quarantine ثم reject.',
      references: [REFS.dmarc],
      service: 'email-domain',
    });
  }
  if (!Number.isFinite(percent) || percent < 100) {
    return open({
      id: 'email.dmarc.partial',
      title: 'DMARC policy does not cover every failing message',
      titleAr: 'سياسة DMARC لا تغطي كل الرسائل الفاشلة',
      severity: 'medium',
      evidence: `pct=${tags.pct} with p=${policy}.`,
      remediation: 'Remove pct or set it to 100 so the policy applies to all failing mail.',
      remediationAr: 'احذف pct أو اضبطه على 100 حتى تنطبق السياسة على كل البريد الفاشل.',
      references: [REFS.dmarc],
      service: 'email-domain',
    });
  }
  return pass({
    id: 'email.dmarc.pass',
    title: `DMARC policy is ${policy}`,
    titleAr: `سياسة DMARC هي ${policy}`,
    evidence: clip(dmarc[0]),
    references: [REFS.dmarc],
    service: 'email-domain',
  });
};

const checkDmarcSubdomains = (dmarc) => {
  if (dmarc.length !== 1) return null;
  const tags = tagsOf(dmarc[0]);
  if (!tags.sp || !enforced(tags.p) || enforced(tags.sp)) return null;
  return open({
    id: 'email.dmarc.subdomains',
    title: 'DMARC does not protect subdomains',
    titleAr: 'سياسة DMARC لا تحمي النطاقات الفرعية',
    severity: 'medium',
    evidence: `p=${tags.p} but sp=${tags.sp}.`,
    remediation: 'Set sp=quarantine or sp=reject, or remove sp so subdomains follow p.',
    remediationAr:
      'اضبط sp=quarantine أو sp=reject، أو احذف sp حتى تتبع النطاقات الفرعية السياسة p.',
    references: [REFS.dmarc],
    service: 'email-domain',
  });
};

const checkDkim = (keys, nullMx, looked) => {
  if (nullMx) return null;
  if (!looked) return null;
  if (!keys.length) {
    return open({
      id: 'email.dkim.not-seen',
      title: 'No DKIM key on the selectors that were checked',
      titleAr: 'لم يُعثر على مفتاح DKIM في المحددات التي فُحصت',
      severity: 'low',
      evidence:
        'DKIM selectors are chosen by the sender, so a key can exist under a name this scan did not see.',
      remediation:
        'Confirm a 2048-bit DKIM key is published for each service that sends mail. This result is not proof the domain has no DKIM.',
      remediationAr:
        'تأكد من نشر مفتاح DKIM بطول 2048 بت لكل خدمة ترسل البريد. هذه النتيجة ليست دليلًا على غياب DKIM.',
      references: [REFS.dkim],
      service: 'email-domain',
    });
  }
  const revoked = keys.filter((key) => key.revoked);
  if (revoked.length === keys.length) {
    return open({
      id: 'email.dkim.revoked',
      title: 'The only DKIM key found is revoked',
      titleAr: 'مفتاح DKIM الوحيد الذي وُجد ملغى',
      severity: 'medium',
      evidence: revoked.map((key) => key.selector).join(', '),
      remediation:
        'Publish a new selector with a 2048-bit key and retire the empty p= record once mail has moved.',
      remediationAr: 'انشر محددًا جديدًا بمفتاح 2048 بت، ثم أزل سجل p= الفارغ بعد انتقال البريد.',
      references: [REFS.dkim],
      service: 'email-domain',
    });
  }
  const weak = keys.filter((key) => key.bits && key.bits < 1024);
  if (weak.length) {
    return open({
      id: 'email.dkim.weak',
      title: 'DKIM key is shorter than 1024 bits',
      titleAr: 'مفتاح DKIM أقصر من 1024 بت',
      severity: 'high',
      evidence: weak.map((key) => `${key.selector} (${key.bits} bits)`).join(', '),
      remediation:
        'Replace it with a 2048-bit RSA key, or an ed25519 key if your receivers accept it.',
      remediationAr:
        'استبدله بمفتاح RSA بطول 2048 بت، أو بمفتاح ed25519 إذا كان المستلمون يقبلونه.',
      references: [REFS.dkim],
      service: 'email-domain',
    });
  }
  const short = keys.filter((key) => key.bits === 1024);
  if (short.length) {
    return open({
      id: 'email.dkim.short',
      title: 'DKIM key is 1024 bits',
      titleAr: 'مفتاح DKIM بطول 1024 بت',
      severity: 'low',
      evidence: short.map((key) => key.selector).join(', '),
      remediation: 'Plan a rotation to a 2048-bit key.',
      remediationAr: 'خطط للتدوير إلى مفتاح بطول 2048 بت.',
      references: [REFS.dkim],
      service: 'email-domain',
    });
  }
  return pass({
    id: 'email.dkim.pass',
    title: 'DKIM key found',
    titleAr: 'تم العثور على مفتاح DKIM',
    evidence: keys.map((key) => key.selector).join(', '),
    references: [REFS.dkim],
    service: 'email-domain',
  });
};

const coversHost = (pattern, host) => {
  const rule = pattern.toLowerCase().replace(/\.$/, '');
  if (rule.startsWith('*.')) return host.split('.').slice(1).join('.') === rule.slice(2);
  return host === rule;
};

const checkMtaSts = (mtaDns, policy, mx, nullMx) => {
  if (nullMx) return null;
  const hosts = mx
    .map((row) =>
      String(row.exchange || '')
        .toLowerCase()
        .replace(/\.$/, ''),
    )
    .filter(Boolean);
  if (!mtaDns.length && !policy) {
    if (!hosts.length) return null;
    return open({
      id: 'email.mta-sts.missing',
      title: 'MTA-STS is not published',
      titleAr: 'لم يُنشر MTA-STS',
      severity: 'info',
      evidence: 'No v=STSv1 TXT record at _mta-sts.',
      remediation:
        'Publish MTA-STS in testing mode, then enforce, so senders cannot be stripped back to cleartext SMTP.',
      remediationAr:
        'انشر MTA-STS في وضع الاختبار ثم في وضع الفرض، حتى لا يُعاد المرسلون إلى SMTP غير مشفّر.',
      references: [REFS.mtaSts],
      service: 'email-domain',
    });
  }
  if (!policy || policy.valid === false || !policy.mode) {
    return open({
      id: 'email.mta-sts.invalid',
      title: 'MTA-STS policy was not confirmed',
      titleAr: 'لم يتم التأكد من سياسة MTA-STS',
      severity: 'medium',
      evidence:
        'A v=STSv1 DNS record was seen, but there was no valid policy file with mode and mx.',
      remediation:
        'Publish a single policy at https://mta-sts.<domain>/.well-known/mta-sts.txt with version STSv1, mode, mx, and max_age.',
      remediationAr:
        'انشر سياسة واحدة على https://mta-sts.<domain>/.well-known/mta-sts.txt تتضمن version: STSv1 وmode وmx وmax_age.',
      references: [REFS.mtaSts],
      service: 'email-domain',
    });
  }
  const patterns = (policy.mx || []).map((item) => String(item));
  const missing = hosts.filter((host) => !patterns.some((pattern) => coversHost(pattern, host)));
  if (missing.length && policy.mode !== 'none') {
    return open({
      id: 'email.mta-sts.mx-gap',
      title: 'MTA-STS policy leaves out a mail host',
      titleAr: 'سياسة MTA-STS تستثني مضيف بريد',
      severity: policy.mode === 'enforce' ? 'high' : 'medium',
      evidence: `Missing from the policy: ${missing.join(', ')}.`,
      remediation:
        'Add an mx line for every host that receives mail. An enforced policy will refuse the ones it omits.',
      remediationAr:
        'أضف سطر mx لكل مضيف يستقبل البريد. السياسة المفروضة ترفض المضيفين الذين لا تذكرهم.',
      references: [REFS.mtaSts],
      service: 'email-domain',
    });
  }
  if (policy.mode !== 'enforce') {
    return open({
      id: 'email.mta-sts.not-enforced',
      title: `MTA-STS is in ${policy.mode} mode`,
      titleAr: `وضع MTA-STS هو ${policy.mode}`,
      severity: 'info',
      evidence: `mode: ${policy.mode}`,
      remediation:
        'Switch the policy to mode: enforce after TLS reports show mail arriving encrypted.',
      remediationAr: 'انقل السياسة إلى mode: enforce بعد أن تؤكد تقارير TLS أن البريد يصل مشفّرًا.',
      references: [REFS.mtaSts],
      service: 'email-domain',
    });
  }
  return pass({
    id: 'email.mta-sts.pass',
    title: 'MTA-STS is enforced',
    titleAr: 'سياسة MTA-STS مفروضة',
    evidence: `mode: enforce; mx: ${patterns.join(', ') || '(none listed)'}`,
    references: [REFS.mtaSts],
    service: 'email-domain',
  });
};

const checkTlsRpt = (tlsRpt, mtaDns, policy) => {
  if (!mtaDns.length && !policy) return null;
  if (tlsRpt.length) {
    return pass({
      id: 'email.tls-rpt.pass',
      title: 'TLS reporting is published',
      titleAr: 'تقارير TLS منشورة',
      evidence: clip(tlsRpt[0]),
      references: [REFS.tlsRpt],
      service: 'email-domain',
    });
  }
  return open({
    id: 'email.tls-rpt.missing',
    title: 'No TLS-RPT record',
    titleAr: 'لا يوجد سجل TLS-RPT',
    severity: 'info',
    evidence: 'MTA-STS is advertised, but _smtp._tls has no v=TLSRPTv1 record.',
    remediation: 'Publish a v=TLSRPTv1 TXT record so you hear when senders cannot negotiate TLS.',
    remediationAr: 'انشر سجل TXT من نوع v=TLSRPTv1 حتى تصلك إشارات فشل التفاوض على TLS.',
    references: [REFS.tlsRpt],
    service: 'email-domain',
  });
};

const checkBimi = (bimi, dmarc) => {
  if (!bimi.length) {
    return open({
      id: 'email.bimi.absent',
      title: 'BIMI is not published',
      titleAr: 'مؤشر BIMI غير منشور',
      severity: 'info',
      evidence: 'No v=BIMI1 record at default._bimi. BIMI is optional.',
      remediation:
        'BIMI is optional. If you want the logo shown, enforce DMARC at 100 percent first, then publish a v=BIMI1 record with an https logo URL.',
      remediationAr:
        'BIMI اختياري. إذا أردت ظهور الشعار، افرض DMARC بنسبة 100 بالمئة أولًا، ثم انشر سجل v=BIMI1 مع رابط https للشعار.',
      references: [REFS.bimi, REFS.dmarc],
      service: 'email-domain',
    });
  }
  const tags = tagsOf(bimi[0]);
  const dmarcTags = dmarc.length === 1 ? tagsOf(dmarc[0]) : {};
  const policy = (dmarcTags.p || '').toLowerCase();
  const percent = dmarcTags.pct === undefined || dmarcTags.pct === '' ? 100 : Number(dmarcTags.pct);
  if (!enforced(policy) || percent < 100) {
    return open({
      id: 'email.bimi.dmarc',
      title: 'BIMI is published without an enforced DMARC policy',
      titleAr: 'BIMI منشور بدون سياسة DMARC مفروضة',
      severity: 'medium',
      evidence: `BIMI record present; DMARC p=${policy || '(none)'} pct=${percent}.`,
      remediation:
        'Mailbox providers ignore BIMI unless DMARC is quarantine or reject at pct=100. Enforce DMARC first.',
      remediationAr:
        'مزودو صناديق البريد يتجاهلون BIMI ما لم تكن سياسة DMARC هي quarantine أو reject عند pct=100. افرض DMARC أولًا.',
      references: [REFS.bimi, REFS.dmarc],
      service: 'email-domain',
    });
  }
  if (!tags.l) {
    return open({
      id: 'email.bimi.logo',
      title: 'BIMI record has no logo location',
      titleAr: 'سجل BIMI بلا موقع للشعار',
      severity: 'low',
      evidence: clip(bimi[0]),
      remediation: 'Add l=https://… pointing at an SVG logo served over HTTPS.',
      remediationAr: 'أضف l=https://… يشير إلى شعار SVG يُقدَّم عبر HTTPS.',
      references: [REFS.bimi],
      service: 'email-domain',
    });
  }
  return pass({
    id: 'email.bimi.pass',
    title: 'BIMI record is published alongside enforced DMARC',
    titleAr: 'سجل BIMI منشور إلى جانب DMARC مفروض',
    evidence: clip(bimi[0]),
    references: [REFS.bimi],
    service: 'email-domain',
  });
};

const checkNullMx = (nullMx) => {
  if (!nullMx) return null;
  return pass({
    id: 'email.null-mx',
    title: 'Domain declares that it does not accept mail',
    titleAr: 'النطاق يصرّح بأنه لا يقبل البريد',
    evidence: 'Null MX (RFC 7505).',
    references: [REFS.nullMx],
    service: 'email-domain',
  });
};

const checkDane = (dane) => {
  if (!Array.isArray(dane) || !dane.length) return [];
  return [
    pass({
      id: 'email.dane.pass',
      title: 'DANE TLSA records were supplied for mail hosts',
      titleAr: 'سجلات DANE TLSA مذكورة لمضيفي البريد',
      evidence: dane.join(', '),
      references: [REFS.dane],
      service: 'email-domain',
    }),
  ];
};
