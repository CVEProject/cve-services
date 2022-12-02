const getConstants = require('../../../src/constants').getConstants
const CONSTANTS = getConstants()

const secretariatHeader = {
  'content-type': 'application/json',
  'CVE-API-ORG': 'mitre',
  'CVE-API-USER': 'cpadro',
  'CVE-API-KEY': 'S96E4QT-SMT4YE3-KX03X6K-4615CED'
}

const owningOrgHeader = {
  'content-type': 'application/json',
  'CVE-API-ORG': 'cisco',
  'CVE-API-USER': 'alopez',
  'CVE-API-KEY': 'SVXPHM9-1VXM0A8-QMG8WN0-29MASSE'
}

const orgHeader = {
  'content-type': 'application/json',
  'CVE-API-ORG': 'apple',
  'CVE-API-USER': 'rgonz',
  'CVE-API-KEY': 'NKWE9PE-42B472A-M5A9W3G-80C31B7'
}

const userAHeader = {
  'content-type': 'application/json',
  'CVE-API-ORG': 'google',
  'CVE-API-USER': 'abaker',
  'CVE-API-KEY': 'TCF25YM-39C4H6D-KA32EGF-V5XSHN3'
}

// admin user header
const userDHeader = {
  'content-type': 'application/json',
  'CVE-API-ORG': 'google',
  'CVE-API-USER': 'gsmith',
  'CVE-API-KEY': 'TCF25YM-39C4H6D-KA32EGF-V5XSHN3'
}

const existentOrg = {
  UUID: '15fd129f-af00-4d8c-8f7b-e19b0587223f',
  authority: {
    active_roles: [CONSTANTS.AUTH_ROLE_ENUM.CNA, CONSTANTS.AUTH_ROLE_ENUM.SECRETARIAT]
  },
  name: 'The MITRE Corporation',
  policies: {
    id_quota: 1000
  },
  short_name: 'mitre'
}

const owningOrg = {
  UUID: '88c02595-c8f7-4864-a0e7-e09b3e1da691',
  authority: {
    active_roles: [CONSTANTS.AUTH_ROLE_ENUM.CNA]
  },
  name: 'Cisco',
  policies: {
    id_quota: 5
  },
  short_name: 'cisco'
}

const existentOrgDummy = {
  UUID: 'ec7fc4ef-a63e-4ac9-b0f4-ac3e57725b4e',
  authority: {
    active_roles: [CONSTANTS.AUTH_ROLE_ENUM.CNA, CONSTANTS.AUTH_ROLE_ENUM.ADP]
  },
  name: 'Google',
  policies: {
    id_quota: 10
  },
  short_name: 'google'
}

const existentOrgDummy2 = {
  UUID: 'eckuc4ef-a63e-89c9-b0f4-ac3erhf5v5be',
  authority: {
    active_roles: [CONSTANTS.AUTH_ROLE_ENUM.ROOT_CNA, CONSTANTS.AUTH_ROLE_ENUM.SECRETARIAT]
  },
  name: 'Oracle',
  policies: {
    id_quota: 15
  },
  short_name: 'oracle'
}

const nonExistentOrg = {
  UUID: '794715e2-ded9-4a16-8dfd-9a062a63e1d5',
  authority: {
    active_roles: [CONSTANTS.AUTH_ROLE_ENUM.CNA]
  },
  name: 'The Oval Office',
  policies: {
    id_quota: 1000
  },
  short_name: 'oval'
}

const toBeDeactivatedOrg = {
  UUID: '345715e2-ded9-4a16-8dfd-9a062a63e1d5',
  authority: {
    active_roles: [CONSTANTS.AUTH_ROLE_ENUM.CNA]
  },
  name: 'OffOn',
  policies: {
    id_quota: 50
  },
  short_name: 'offon'
}

const toBeActivatedOrg = {
  UUID: '543715e2-ded9-4a16-8dfd-9a062a63e1d5',
  authority: {
    active_roles: []
  },
  name: 'OnOff',
  policies: {
    id_quota: 75
  },
  short_name: 'OnOff'
}

// For validating policies.id_quota below minimum
const orgWithNegativeIdQuota = {
  UUID: '0zoiz5ht-meym-9pj7-95de-ub4ge22rfazn',
  authority: {
    active_roles: [CONSTANTS.AUTH_ROLE_ENUM.CNA]
  },
  name: 'Stark Industries',
  policies: {
    id_quota: -1
  },
  short_name: 'stark'
}

// For validating policies.id_quota above maximum
const orgExceedingMaxIdQuota = {
  UUID: '0zoir4ht-meym-90j7-95de-ub4ge77rfaz8n',
  authority: {
    active_roles: [CONSTANTS.AUTH_ROLE_ENUM.CNA]
  },
  name: 'E.E.A.',
  policies: {
    id_quota: 100500
  },
  short_name: 'eea'
}

const orgWithZeroIdQuota = {
  UUID: 'eq3ecuob-yqbf-eheo-piaq-j9zfna86agw4',
  authority: {
    active_roles: [CONSTANTS.AUTH_ROLE_ENUM.CNA]
  },
  name: 'Wayne Enterprises',
  policies: {
    id_quota: 0
  },
  short_name: 'wayne'
}

const existentUser = {
  UUID: 'e13186d5-ce3d-4fd9-aecd-8698c26897f2',
  org_UUID: existentOrg.UUID,
  name: {
    first: 'Cristina',
    last: 'Padro'
  },
  authority: {
    active_roles: []
  },
  secret: '$argon2i$v=19$m=4096,t=3,p=1$+qGHEfH5h4/tk404iWBxFw$xV96/b4NvQVvlZIq57wTS8s7gfKzsfMXRiOyf3ffgcw',
  username: 'cpadro',
  active: true
}

const existentUserDummy = {
  UUID: 'e13556d5-ce3d-4fd9-aecd-8698c26898g5',
  org_UUID: owningOrg.UUID,
  name: {
    first: 'Luis',
    last: 'Ramirez'
  },
  authority: {
    active_roles: []
  },
  secret: '$argon2i$v=19$m=4096,t=3,p=1$yHw6o9QK1Fe3Zn/bzCMejw$A44O4TueJT12iKu1NlhZpIoTYPIOV5KERoJiwAWUPYk',
  username: 'lramirez',
  active: true
}

const existentUserDummy2 = {
  UUID: 'e13gfvh6d5-783d-4fd9-a90d-869yjvjgk8g5',
  org_UUID: existentOrgDummy2.UUID,
  name: {
    first: 'Jose',
    last: 'Alamo',
    middle: 'Natalicio',
    suffix: 'Jr.'
  },
  authority: {
    active_roles: []
  },
  secret: '$argon2i$v=19$m=4096,t=3,p=1$QAwCe7bO5FYsroeiAM+FWw$f3nJRqhYxScf+2eBfBOu18OkIlexFsgOVJW/++8n9l0',
  username: 'natalm',
  active: false
}

const nonExistentUser = {
  UUID: '7d277951-53cb-45c5-82a0-9f1f9c8d29c7',
  org_UUID: existentOrg.UUID,
  name: {
    first: 'David',
    last: 'Smith',
    suffix: 'Sr.'
  },
  authority: {
    active_roles: []
  },
  secret: '$argon2i$v=19$m=4096,t=3,p=1$HQuqVd6W5rxX0VvXtI178Q$kPKWWjIq1czpJFfYZBvpq04SupCfAR/dReDQvgVS+P0',
  username: 'dsmith',
  active: false
}

const userA = {
  username: 'abaker',
  active: true,
  name: {
    first: 'Ashley',
    last: 'Baker',
    middle: 'N',
    suffix: 'I'
  },
  authority: {
    active_roles: []
  },
  org_UUID: existentOrgDummy.UUID,
  UUID: '33394284-4acf-424f-b199-9e57656ee451',
  secret: '$argon2i$v=19$m=4096,t=3,p=1$meXeqZas6Ba2eQrIb3xbiA$x8KRFqYVuvlvsyMiUA2/hSaFbd2mxaKhEM5rXUfx9sw'
}

const userB = { // same username as userA but different org_UUID
  username: 'abaker',
  active: true,
  name: {
    first: 'Ashley',
    last: 'Baker',
    middle: 'N',
    suffix: 'I'
  },
  authority: {
    active_roles: []
  },
  org_UUID: owningOrg.UUID,
  UUID: '33394284-4acf-424f-b199-9e57656ff451',
  secret: '$argon2i$v=19$m=4096,t=3,p=1$meXeqZas6Ba2eQrIb3xbiA$x8KRFqYVuvlvsyMiUA2/hSaFbd2mxaKhEM5rXUfx9sw'
}

const userC = { // same org_UUID as userA but different username
  username: 'wbalck',
  active: true,
  name: {
    first: 'William',
    last: 'Black'
  },
  authority: {
    active_roles: []
  },
  org_UUID: existentOrgDummy.UUID,
  UUID: '33394284-4acf-423b-b199-9e57656ee451',
  secret: '$argon2i$v=19$m=4096,t=3,p=1$meXeqZas6Ba2eQrIb3xbiA$x8KRFqYVuvlvsyMiUA2/hSaFbd2mxaKhEM5rXUfx9sw'
}

const userD = { // same org_UUID as userA but org admin
  username: 'gsmith',
  active: true,
  name: {
    first: 'Gregory',
    last: 'Smith'
  },
  authority: {
    active_roles: [CONSTANTS.USER_ROLE_ENUM.ADMIN]
  },
  org_UUID: existentOrgDummy.UUID,
  UUID: '33394284-4acf-423b-b199-9e57656ee451',
  secret: '$argon2i$v=19$m=4096,t=3,p=1$meXeqZas6Ba2eQrIb3xbiA$x8KRFqYVuvlvsyMiUA2/hSaFbd2mxaKhEM5rXUfx9sw'
}

const allOrgs = [existentOrg, owningOrg, existentOrgDummy, existentOrgDummy2, toBeDeactivatedOrg, toBeActivatedOrg, orgWithNegativeIdQuota, orgExceedingMaxIdQuota, orgWithZeroIdQuota]

const allOwningOrgUsers = [
  existentUserDummy,
  {
    org_UUID: owningOrg.UUID,
    username: 'travispost',
    UUID: '48e89261-5797-4614-81ae-4bf0595b0689',
    active: true,
    name: {
      first: 'Travis',
      last: 'Post',
      middle: 'A.'
    },
    authority: {
      active_roles: []
    },
    secret: '$argon2i$v=19$m=4096,t=3,p=1$+oG246Lm4fOnSTFJZdAfPA$PQIHmY1LgzJn0IYSTlaNqGr00K9f2F0uZQgboQnqRjw'
  },
  {
    org_UUID: owningOrg.UUID,
    username: 'duaspade',
    UUID: 'cd35c708-c6c9-4c52-89e3-c053c2b8cbf5',
    active: true,
    name: {
      first: 'Dua',
      last: 'Spade'
    },
    authority: {
      active_roles: []
    },
    secret: '$argon2i$v=19$m=4096,t=3,p=1$VHsBUuc2pGTYL9seHOJ8Vw$hQXRlzUIJklxYhRoMmwSNScyulMdR4IGmxxyALe6jsw'
  },
  {
    org_UUID: owningOrg.UUID,
    username: 'colewhite',
    UUID: '9624d11f-28c5-4717-8039-3752bf9b03e0',
    active: true,
    name: {
      first: 'Cole',
      last: 'White',
      suffix: 'IV'
    },
    authority: {
      active_roles: []
    },
    secret: '$argon2i$v=19$m=4096,t=3,p=1$NDA1tIslsvipxuOI8raZZQ$FJk57PhH2C+h/L4snN5gRqRsPF2VNHO1Wm+pLo+ACqo'
  },
  {
    org_UUID: owningOrg.UUID,
    username: 'adamlux',
    UUID: '8a6ecd6a-7f7e-48c1-b0d6-8691a388eb66',
    active: true,
    name: {
      first: 'Adam',
      last: 'Lux'
    },
    authority: {
      active_roles: []
    },
    secret: '$argon2i$v=19$m=4096,t=3,p=1$QY6juc/rjf1XOUpIjRJ1/w$KyDUmzLRHymH0HXO70/pgUrkkLTJ4EUs508b517ama4'
  }
]

module.exports = {
  userA,
  userB,
  userC,
  userD,
  allOrgs,
  allOwningOrgUsers,
  secretariatHeader,
  owningOrgHeader,
  userAHeader,
  userDHeader,
  orgHeader,
  owningOrg,
  existentOrg,
  existentOrgDummy,
  existentUserDummy2,
  nonExistentOrg,
  existentUser,
  existentUserDummy,
  existentOrgDummy2,
  nonExistentUser,
  orgWithNegativeIdQuota,
  orgExceedingMaxIdQuota,
  orgWithZeroIdQuota,
  toBeDeactivatedOrg,
  toBeActivatedOrg
}
