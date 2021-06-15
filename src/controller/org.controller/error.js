const idrErr = require('../../utils/error')

class OrgControllerError extends idrErr.IDRError {
  orgDneParam (shortname) { // org
    const err = {}
    err.error = 'ORG_DNE_PARAM'
    err.message = `The '${shortname}' organization designated by the shortname parameter does not exist.`
    return err
  }

  userDne (username) { // org
    const err = {}
    err.error = 'USER_DNE'
    err.message = `The user '${username}' designated by the username parameter does not exist.`
    return err
  }

  notSameOrgOrSecretariat () { // org
    const err = {}
    err.error = 'NOT_SAME_ORG_OR_SECRETARIAT'
    err.message = 'This information can only be viewed by the users of the same organization or the Secretariat.'
    return err
  }

  orgExists (shortname) { // org
    const err = {}
    err.error = 'ORG_EXISTS'
    err.message = `The '${shortname}' organization already exists.`
    return err
  }

  userExists (username) { // org
    const err = {}
    err.error = 'USER_EXISTS'
    err.message = `The user '${username}' already exists.`
    return err
  }

  uuidProvided () { // org
    const err = {}
    err.error = 'UUID_PROVIDED'
    err.message = 'Providing UUIDs for user creation or update is not allowed.'
    return err
  }

  duplicateUsername (shortname, username) { // org
    const err = {}
    err.error = 'DUPLICATE_USERNAME'
    err.message = `The user could not be updated because the '${shortname}' organization contains another user with the username '${username}'.`
    return err
  }

  duplicateShortname (shortname) { // org
    const err = {}
    err.error = 'DUPLICATE_SHORTNAME'
    err.message = `The organization cannot be renamed as '${shortname}' because this shortname is used by another organization.`
    return err
  }
}

module.exports = {
  OrgControllerError
}
