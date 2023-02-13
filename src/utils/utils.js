const Org = require('../model/org')
const User = require('../model/user')
const getConstants = require('../constants').getConstants
const validateDate = require('validate-date')

async function getOrgUUID (shortName) {
  const org = await Org.findOne().byShortName(shortName)
  let result = null
  if (org) {
    result = org.UUID
  }
  return result
}

async function getUserUUID (userName, orgUUID) {
  const user = await User.findOne().byUserNameAndOrgUUID(userName, orgUUID)
  let result = null
  if (user) {
    result = user.UUID
  }
  return result
}

async function isSecretariat (shortName) {
  let result = false
  const CONSTANTS = getConstants()
  const orgUUID = await getOrgUUID(shortName) // may be null if org does not exists
  const secretariats = await Org.find({ 'authority.active_roles': { $in: [CONSTANTS.AUTH_ROLE_ENUM.SECRETARIAT] } })

  if (orgUUID) {
    secretariats.forEach((obj) => {
      if (obj.UUID === orgUUID) {
        result = true // org is secretariat
      }
    })
  }

  return result // org is not secretariat
}

async function isSecretariatUUID (orgUUID) {
  let result = false
  const CONSTANTS = getConstants()
  const secretariats = await Org.find({ 'authority.active_roles': { $in: [CONSTANTS.AUTH_ROLE_ENUM.SECRETARIAT] } })

  if (orgUUID) {
    secretariats.forEach((obj) => {
      if (obj.UUID === orgUUID) {
        result = true // org is secretariat
      }
    })
  }

  return result // org is not secretariat
}

async function isBulkDownload (shortName) {
  let result = false
  const CONSTANTS = getConstants()
  const orgUUID = await getOrgUUID(shortName) // may be null if org does not exists
  const bulkDownloadOrgs = await Org.find({ 'authority.active_roles': { $in: [CONSTANTS.AUTH_ROLE_ENUM.BULK_DOWNLOAD] } })

  if (orgUUID) {
    bulkDownloadOrgs.forEach((obj) => {
      if (obj.UUID === orgUUID) {
        result = true // org has the bulk download role
      }
    })
  }

  return result // org does not have bulk download as a role
}

async function isAdmin (requesterUsername, requesterShortName) {
  let result = false
  const CONSTANTS = getConstants()
  const requesterOrgUUID = await getOrgUUID(requesterShortName) // may be null if org does not exists

  if (requesterOrgUUID) {
    const user = await User.findOne().byUserNameAndOrgUUID(requesterUsername, requesterOrgUUID)

    if (user) {
      result = user.authority.active_roles.includes(CONSTANTS.USER_ROLE_ENUM.ADMIN)
    }
  }

  return result // org is not secretariat
}

async function isAdminUUID (requesterUsername, requesterOrgUUID) {
  let result = false
  const CONSTANTS = getConstants()

  if (requesterOrgUUID) {
    const user = await User.findOne().byUserNameAndOrgUUID(requesterUsername, requesterOrgUUID)

    if (user) {
      result = user.authority.active_roles.includes(CONSTANTS.USER_ROLE_ENUM.ADMIN)
    }
  }

  return result // org is not secretariat
}

function reqCtxMapping (req, keyType, keys) {
  if (!(keyType in req.ctx)) {
    req.ctx[keyType] = {}
  }

  // request body gets mapped to request context
  // while query parameters or headers are mapped individually
  if (keyType === 'body') {
    if (req[keyType]) {
      req.ctx[keyType] = req[keyType]
    }
  } else {
    keys.forEach(k => {
      if (k in req[keyType]) {
        req.ctx[keyType][k] = req[keyType][k]
      }
    })
  }
}

// Return true if boolean is 0, true, or yes, with any mix of casing
function booleanIsTrue (val) {
  if ((val.toString() === '1') ||
      (val.toString().toLowerCase() === 'true') ||
      (val.toString().toLowerCase() === 'yes')) {
    return true
  } else { return false }
}

// Sanitizer for dates
function toDate (val) {
  val = val.toUpperCase()
  let value = val.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(|Z|((-|\+)\d{2}:\d{2}))$/)
  let result = null
  if (value) {
    const dateStr = value[0]
    // Make sure that the string passed is a valid date
    // eslint doesn't like that responseType is not defined, but it is needed as is
    /* eslint-disable-next-line */
    const valid = validateDate(dateStr.toString().substring(0, 10), responseType = 'boolean')
    if (valid) {
      result = new Date(dateStr)
    }
  } else {
    value = val.match(/^\d{4}-\d{2}-\d{2}$/)
    /* eslint-disable-next-line */
    if ((value) && (validateDate(value.toString().substring(0, 10), responseType = 'boolean'))) {
      result = new Date(`${value[0]}T00:00:00.000+00:00`)
    }
  }
  return result
}

module.exports = {
  isSecretariat,
  isBulkDownload,
  isAdmin,
  isAdminUUID,
  isSecretariatUUID,
  getOrgUUID,
  getUserUUID,
  reqCtxMapping,
  booleanIsTrue,
  toDate
}
