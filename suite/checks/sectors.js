import { finding } from '../findings.js';
import { REFS } from '../refs.js';

const pack = (id, title, titleAr, plain, plainAr) =>
  finding({
    id: `sector.${id}`,
    title,
    titleAr,
    severity: 'info',
    evidence:
      'Matched from mail hosts, headers, or page text. This is a hint for the fix wording, not a claim about the contract with that vendor.',
    remediation: plain,
    remediationAr: plainAr,
    plainFix: plain,
    references: [REFS.spf, REFS.dmarc],
    service: 'email-domain',
    effort: 'low',
    impact: 'medium',
  });

export const detectSectors = (observations = {}) => {
  const mx = (observations.dns?.mx || []).map((row) =>
    String(row.exchange || '')
      .toLowerCase()
      .replace(/\.$/, ''),
  );
  const headers = observations.http?.headers || {};
  const blob = `${JSON.stringify(headers)} ${observations.http?.bodySnippet || ''} ${observations.http?.body || ''}`;
  const packs = [];
  if (mx.some((host) => host.endsWith('outlook.com') || host.includes('protection.outlook.com'))) {
    packs.push('microsoft-365');
  }
  if (mx.some((host) => host.endsWith('google.com') || host.endsWith('googlemail.com'))) {
    packs.push('google-workspace');
  }
  if (/woocommerce/i.test(blob)) packs.push('woocommerce');
  if (/cdn\.shopify|myshopify|x-shopid/i.test(blob)) packs.push('shopify');
  if (/litespeed|cpanel|plesk|hostinger|aedns|etisalat|tasjeel/i.test(blob)) {
    packs.push('uae-shared-hosting');
  }
  return packs;
};

const COPY = {
  'microsoft-365': pack(
    'microsoft-365',
    'Mail host looks like Microsoft 365',
    'مضيف البريد يبدو Microsoft 365',
    'For Microsoft 365, SPF should include spf.protection.outlook.com, and DKIM is usually selector1 and selector2. Turn on DMARC after those pass.',
    'لـ Microsoft 365، يجب أن يتضمن SPF القيمة spf.protection.outlook.com، وDKIM غالبًا selector1 وselector2. فعّل DMARC بعد أن يجتازا الفحص.',
  ),
  'google-workspace': pack(
    'google-workspace',
    'Mail host looks like Google Workspace',
    'مضيف البريد يبدو Google Workspace',
    'For Google Workspace, SPF should include _spf.google.com and DKIM is often the google selector. Enforce DMARC once reports look clean.',
    'لـ Google Workspace، يجب أن يتضمن SPF القيمة _spf.google.com، وDKIM غالبًا المحدد google. افرض DMARC عندما تبدو التقارير سليمة.',
  ),
  woocommerce: pack(
    'woocommerce',
    'Site looks like WooCommerce',
    'الموقع يبدو WooCommerce',
    'Keep WordPress, WooCommerce, and PHP on supported versions. Remove public backups and unused admin plugins. Checkout pages should be HTTPS only.',
    'أبقِ ووردبريس وWooCommerce وPHP على إصدارات مدعومة. احذف النسخ العامة والإضافات الإدارية غير المستخدمة. صفحات الدفع يجب أن تكون HTTPS فقط.',
  ),
  shopify: pack(
    'shopify',
    'Site looks like Shopify',
    'الموقع يبدو Shopify',
    'Shopify manages the store TLS. Your own domain still needs SPF, DKIM, and DMARC for the mail you send, and a CAA record if you issue certificates elsewhere.',
    'شوبيفاي يدير تشفير المتجر. نطاقك ما زال يحتاج SPF وDKIM وDMARC للبريد الذي ترسله، وسجل CAA إذا كنت تصدر شهادات من جهة أخرى.',
  ),
  'uae-shared-hosting': pack(
    'uae-shared-hosting',
    'Site looks like shared hosting common in the UAE',
    'الموقع يبدو استضافة مشتركة شائعة في الإمارات',
    'On cPanel, Plesk, or LiteSpeed hosting, turn off directory indexes, remove public backups, and keep the panel off the public internet. Ask the host which mail servers to put in SPF.',
    'على استضافة cPanel أو Plesk أو LiteSpeed، عطّل فهارس المجلدات، واحذف النسخ العامة، وأبقِ لوحة التحكم بعيدًا عن الإنترنت. اسأل المستضيف أي خوادم بريد تضعها في SPF.',
  ),
};

export const sectorFindings = (observations) =>
  detectSectors(observations)
    .map((id) => COPY[id])
    .filter(Boolean);
