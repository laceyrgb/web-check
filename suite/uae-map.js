// Control ids are taken from the UAE Information Assurance Regulation v1.1 published by TDRA.
// v2.1 (reported November 2025) reorders some families. These ids are reference-only until a
// reviewer checks the current text. DESC ISR clause numbers are not invented here.

export const UAE_IA_SOURCE =
  'https://tdra.gov.ae/-/media/About/regulations-and-ruling/EN/UAE-Information-Assurance-Regulation-v1-1-pdf.ashx';

export const DESC_SOURCE = 'https://www.desc.gov.ae/regulations/licenses/';

export const PDPL_SOURCE = 'https://www.uaelegislation.gov.ae/en/legislations/1972';

export const DESC_NOTE =
  'Reference only: DESC Information Security Regulation applies to Dubai government entities. This scan is not a DESC assessment and does not cite ISR clause numbers.';

export const DESC_NOTE_AR =
  'للاسترشاد فقط: لائحة أمن المعلومات لدى مركز دبي للأمن الإلكتروني تخص جهات حكومة دبي. هذا الفحص ليس تقييم DESC ولا يذكر أرقام بنود لم تُراجع على النص الرسمي.';

export const CONTROLS = {
  'email-domain': {
    id: 'T4.2.4',
    name: 'Electronic Messaging',
  },
  'tls-headers': {
    id: 'T7.4.1',
    name: 'Policy on the Use of Cryptographic Controls',
  },
  'dns-hygiene': {
    id: 'T4.5.2',
    name: 'Security of Network Services',
  },
  'attack-surface': {
    id: 'T1.2.1',
    name: 'Inventory of Assets',
  },
  vulnerability: {
    id: 'T7.7.1',
    name: 'Control of Technical Vulnerabilities',
  },
  legal: {
    id: 'M5.2.1',
    name: 'Identification of Applicable Legislation',
  },
};

export const controlFor = (service) => CONTROLS[service] || CONTROLS.legal;
