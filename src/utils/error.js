class IDRError {
  badInput (details) { // super
    const err = {}
    err.error = 'BAD_INPUT'
    err.message = 'Parameters were invalid'
    err.details = details
    return err
  }

  orgDne (shortname, paramName, paramType) { // super
    const err = {}
    err.error = 'ORG_DNE'
    err.message = `The organization '${shortname}' designated by the ${paramName} ${paramType} parameter does not exist.`
    return err
  }

  cveIdNotFound (id) { // super
    const err = {}
    err.error = 'CVE_ID_NOT_FOUND'
    err.message = `${id} not found`
    return err
  }

  serverError () { // super
    const err = {}
    err.error = 'INTERNAL_SERVER_ERROR'
    err.message = 'Internal Server Error'
    return err
  }

  serviceNotAvailable () { // super
    const err = {}
    err.error = 'SERVICE_NOT_AVAILABLE'
    err.message = 'This service appears to not be available.'
    return err
  }

  connectionError () { // super
    const err = {}
    err.error = 'CONNECTION_ERROR'
    err.message = 'Mongoose Connection Error: Something went wrong!'
    return err
  }

  notFound () { // super
    const err = {}
    err.error = 'NOT_FOUND'
    err.message = '404: resource not found'
    return err
  }

  fileWriteError (details) { // super
    const err = {}
    err.error = 'FILE_WRITE_ERROR'
    err.message = 'File Write Error: Something went wrong!'
    err.details = details
    return err
  }

  fileDeleteError (details) { // super
    const err = {}
    err.error = 'FILE_DELETE_ERROR'
    err.message = 'File Delete Error: Something went wrong!'
    err.details = details
    return err
  }

  invalidUUID (uuid) { // super
    const err = {}
    err.error = 'INVALID_UUID'
    err.message = `The user with UUID '${uuid}' has an invalid UUID secret. Aborting script.`
    return err
  }

  notSameUserOrSecretariat () { // super
    const err = {}
    err.error = 'NOT_SAME_USER_OR_SECRETARIAT'
    err.message = 'This information can only be viewed or modified by the Secretariat, an Org Admin or if the requester is the user.'
    return err
  }

  notOrgAdminOrSecretariat () { // super
    const err = {}
    err.error = 'NOT_ORG_ADMIN_OR_SECRETARIAT'
    err.message = 'Users can only be created by the Secretariat or Org Admin.'
    return err
  }

  notOrgAdminOrSecretariatUpdate () {
    const err = {}
    err.error = 'NOT_ORG_ADMIN_OR_SECRETARIAT_UPDATE'
    err.message = 'Contact your org Admin to update fields other than your name.'
    return err
  }

  invalidJsonSchema (errors) { // mw
    const err = {}
    err.error = 'INVALID_JSON_SCHEMA'
    err.message = 'CVE JSON schema validation FAILED.'
    err.details = {
      errors: errors
    }

    return err
  }

  tooManyRequests () {
    return {
      error: 'TOO_MANY_REQUESTS',
      message: 'Too many requests. Please try again later.'
    }
  }
}

module.exports = {
  IDRError
}
