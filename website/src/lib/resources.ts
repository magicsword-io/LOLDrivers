const repository =
  'https://github.com/magicsword-io/LOLDrivers/tree/main/detections';
export const detections = [
  {
    name: 'Sigma',
    description: 'Driver-load detection rules by hash and filename.',
    url: `${repository}/sigma`,
  },
  {
    name: 'YARA',
    description: 'Exact-match and threat-hunting rules for driver samples.',
    url: `${repository}/yara`,
  },
  {
    name: 'Sysmon',
    description: 'Driver-load detection and file-blocking configurations.',
    url: `${repository}/sysmon`,
  },
  {
    name: 'WDAC',
    description: 'Windows application control policies.',
    url: `${repository}/wdac`,
  },
  {
    name: 'ClamAV',
    description: 'Community-maintained driver hash signatures.',
    url: `${repository}/av`,
  },
];
export const tools = [
  {
    name: 'LOLDrivers Client',
    description: 'Windows driver scanning',
    maintainer: 'rtfmkiesel',
    url: 'https://github.com/rtfmkiesel/loldrivers-client',
  },
  {
    name: 'PowerShell Scanner',
    description: 'Compare local drivers with the catalog',
    maintainer: 'Oddvar Moe (api0cradle)',
    url: 'https://gist.github.com/api0cradle/d52832e36aaf86d443b3b9f58d20c01d#file-check_vulnerabledrivers-ps1',
  },
  {
    name: 'Nessus',
    description: 'LOLDriver Detection (Windows) plugin',
    maintainer: 'Tenable',
    url: 'https://www.tenable.com/plugins/nessus/204959',
  },
  {
    name: 'Velociraptor',
    description: 'Driver hunting with YARA',
    maintainer: 'Velociraptor community',
    url: 'https://docs.velociraptor.app/exchange/artifacts/pages/windows.hunter.yara.loldrivers/',
  },
];
