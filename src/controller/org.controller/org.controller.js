require('dotenv').config()
const User = require('../../model/user')
const Org = require('../../model/org')
const logger = require('../../middleware/logger')
const argon2 = require('argon2')
const CONSTANTS = require('../../constants')
const cryptoRandomString = require('crypto-random-string')
const uuid = require('uuid')
const errors = require('./error')
const error = new errors.OrgControllerError()
const uuidAPIKey = require('uuid-apikey')

// Get the details of all orgs
async function getOrgs (req, res, next) {
  try {
    const options = CONSTANTS.PAGINATOR_OPTIONS
    options.sort = { short_name: 'asc' }
    options.page = req.ctx.query.page ? parseInt(req.ctx.query.page) : CONSTANTS.PAGINATOR_PAGE // if 'page' query parameter is not defined, set 'page' to the default page value
    const repo = req.ctx.repositories.getOrgRepository()

    const agt = setAggregateOrgObj({})
    const pg = await repo.aggregatePaginate(agt, options)
    const payload = { organizations: pg.itemsList }

    if (pg.itemCount >= CONSTANTS.PAGINATOR_OPTIONS.limit) {
      payload.totalCount = pg.itemCount
      payload.itemsPerPage = pg.itemsPerPage
      payload.pageCount = pg.pageCount
      payload.currentPage = pg.currentPage
      payload.prevPage = pg.prevPage
      payload.nextPage = pg.nextPage
    }

    logger.info({ uuid: req.ctx.uuid, message: 'The orgs were sent to the user.' })
    return res.status(200).json(payload)
  } catch (err) {
    next(err)
  }
}

// Get the details of a single org for the specified shortname
async function getOrg (req, res, next) {
  try {
    const orgShortName = req.ctx.org
    const identifier = req.ctx.params.identifier
    const repo = req.ctx.repositories.getOrgRepository()
    const isSecretariat = await repo.isSecretariat(orgShortName)
    const org = await repo.findOneByShortName(orgShortName)
    let orgIdentifer = orgShortName
    let agt = setAggregateOrgObj({ short_name: identifier })

    // check if identifier is uuid and if so, reassign agt and orgIdentifier
    if (uuidAPIKey.isUUID(identifier)) {
      orgIdentifer = org.UUID
      agt = setAggregateOrgObj({ UUID: identifier })
    }

    if (orgIdentifer !== identifier && !isSecretariat) {
      logger.info({ uuid: req.ctx.uuid, message: identifier + ' organization can only be viewed by the users of the same organization or the Secretariat.' })
      return res.status(403).json(error.notSameOrgOrSecretariat())
    }

    let result = await repo.aggregate(agt)
    result = result.length > 0 ? result[0] : null

    if (!result) { // an empty result can only happen if the requestor is the Secretariat
      logger.info({ uuid: req.ctx.uuid, message: identifier + ' organization does not exist.' })
      return res.status(404).json(error.orgDneParam(identifier))
    }

    logger.info({ uuid: req.ctx.uuid, message: identifier + ' organization was sent to the user.', org: result })
    return res.status(200).json(result)
  } catch (err) {
    next(err)
  }
}

// Get the details of all users from an org given the specified shortname
async function getUsers (req, res, next) {
  try {
    const options = CONSTANTS.PAGINATOR_OPTIONS
    options.sort = { username: 'asc' }
    options.page = req.ctx.query.page ? parseInt(req.ctx.query.page) : CONSTANTS.PAGINATOR_PAGE // if 'page' query parameter is not defined, set 'page' to the default page value
    const shortName = req.ctx.org
    const orgShortName = req.ctx.params.shortname
    const orgRepo = req.ctx.repositories.getOrgRepository()
    const userRepo = req.ctx.repositories.getUserRepository()
    const orgUUID = await orgRepo.getOrgUUID(orgShortName)
    const isSecretariat = await orgRepo.isSecretariat(shortName)

    if (!orgUUID) {
      logger.info({ uuid: req.ctx.uuid, message: orgShortName + ' organization does not exist.' })
      return res.status(404).json(error.orgDneParam(orgShortName))
    }

    if (orgShortName !== shortName && !isSecretariat) {
      logger.info({ uuid: req.ctx.uuid, message: orgShortName + ' organization can only be viewed by the users of the same organization or the Secretariat.' })
      return res.status(403).json(error.notSameOrgOrSecretariat())
    }

    const agt = setAggregateUserObj({ org_UUID: orgUUID })
    const pg = await userRepo.aggregatePaginate(agt, options)
    const payload = { users: pg.itemsList }

    if (pg.itemCount >= CONSTANTS.PAGINATOR_OPTIONS.limit) {
      payload.totalCount = pg.itemCount
      payload.itemsPerPage = pg.itemsPerPage
      payload.pageCount = pg.pageCount
      payload.currentPage = pg.currentPage
      payload.prevPage = pg.prevPage
      payload.nextPage = pg.nextPage
    }

    logger.info({ uuid: req.ctx.uuid, message: `The users of ${orgShortName} organization were sent to the user.` })
    return res.status(200).json(payload)
  } catch (err) {
    next(err)
  }
}

// Get the details of a single user for the specified username
async function getUser (req, res, next) {
  try {
    const shortName = req.ctx.org
    const username = req.ctx.params.username
    const orgShortName = req.ctx.params.shortname
    const orgRepo = req.ctx.repositories.getOrgRepository()
    const isSecretariat = await orgRepo.isSecretariat(shortName)

    if (orgShortName !== shortName && !isSecretariat) {
      logger.info({ uuid: req.ctx.uuid, message: shortName + ' organization can only be viewed by that organization\'s users or the Secretariat.' })
      return res.status(403).json(error.notSameOrgOrSecretariat())
    }

    const orgUUID = await orgRepo.getOrgUUID(orgShortName)
    if (!orgUUID) { // the org can only be non-existent if the requestor is the Secretariat
      logger.info({ uuid: req.ctx.uuid, message: orgShortName + ' organization does not exist.' })
      return res.status(404).json(error.orgDneParam(orgShortName))
    }

    const userRepo = req.ctx.repositories.getUserRepository()
    const agt = setAggregateUserObj({ username: username, org_UUID: orgUUID })
    let result = await userRepo.aggregate(agt)
    result = result.length > 0 ? result[0] : null

    if (!result) {
      logger.info({ uuid: req.ctx.uuid, message: username + ' does not exist.' })
      return res.status(404).json(error.userDne(username))
    }

    logger.info({ uuid: req.ctx.uuid, message: username + ' was sent to the user.', user: result })
    return res.status(200).json(result)
  } catch (err) {
    next(err)
  }
}

// Get details on ID quota for an org with the specified org shortname
async function getOrgIdQuota (req, res, next) {
  try {
    const orgShortName = req.ctx.org
    const shortName = req.ctx.params.shortname
    const repo = req.ctx.repositories.getOrgRepository()
    const isSecretariat = await repo.isSecretariat(orgShortName)

    if (orgShortName !== shortName && !isSecretariat) {
      logger.info({ uuid: req.ctx.uuid, message: shortName + ' organization id quota can only be viewed by the users of the same organization or the Secretariat.' })
      return res.status(403).json(error.notSameOrgOrSecretariat())
    }

    let result = await repo.findOneByShortName(shortName)
    if (!result) { // a null result can only happen if the requestor is the Secretariat
      logger.info({ uuid: req.ctx.uuid, message: shortName + ' organization does not exist.' })
      return res.status(404).json(error.orgDneParam(shortName))
    }

    const returnPayload = {
      id_quota: result.policies.id_quota,
      total_reserved: null,
      available: null
    }

    const query = {
      owning_cna: await repo.getOrgUUID(shortName),
      state: CONSTANTS.CVE_STATES.RESERVED
    }
    const cveIdRepo = req.ctx.repositories.getCveIdRepository()
    result = await cveIdRepo.countDocuments(query)
    returnPayload.total_reserved = result
    returnPayload.available = returnPayload.id_quota - returnPayload.total_reserved

    logger.info({ uuid: req.ctx.uuid, message: 'The organization\'s id quota was returned to the user.', details: returnPayload })
    return res.status(200).json(returnPayload)
  } catch (err) {
    next(err)
  }
}

// Creates a new org only if the org doesn't exist for the specified shortname. If the org exists, we do not update the org.
async function createOrg (req, res, next) {
  try {
    const newOrg = new Org()
    const orgRepo = req.ctx.repositories.getOrgRepository()

    Object.keys(req.ctx.body).forEach(k => {
      const key = k.toLowerCase()

      if (key === 'short_name') {
        newOrg.short_name = req.ctx.body.short_name
      } else if (key === 'name') {
        newOrg.name = req.ctx.body.name
      } else if (key === 'authority') {
        if (req.ctx.body.authority.active_roles) {
          newOrg.authority.active_roles = req.ctx.body.authority.active_roles
        }
      } else if (key === 'policies') {
        if (req.ctx.body.policies.id_quota) {
          newOrg.policies.id_quota = req.ctx.body.policies.id_quota
        }
      } else if (key === 'uuid') {
        return res.status(400).json(error.uuidProvided())
      }
    })

    let result = await orgRepo.findOneByShortName(newOrg.short_name) // Find org in MongoDB
    if (result) {
      logger.info({ uuid: req.ctx.uuid, message: newOrg.short_name + ' organization was not created because it already exists.' })
      return res.status(400).json(error.orgExists(newOrg.short_name))
    }

    newOrg.inUse = false
    newOrg.UUID = uuid.v4()
    newOrg.authority.active_roles = [CONSTANTS.AUTH_ROLE_ENUM.CNA] // default role

    if (!newOrg.policies.id_quota) {
      newOrg.policies.id_quota = CONSTANTS.DEFAULT_ID_QUOTA
    }

    await orgRepo.updateByOrgUUID(newOrg.UUID, newOrg, { upsert: true }) // Create org in MongoDB if it doesn't exist
    const agt = setAggregateOrgObj({ short_name: newOrg.short_name })
    result = await orgRepo.aggregate(agt)
    result = result.length > 0 ? result[0] : null

    const responseMessage = {
      message: newOrg.short_name + ' organization was successfully created.',
      created: result
    }

    const payload = {
      action: 'create_org',
      change: newOrg.short_name + ' organization was successfully created.',
      req_UUID: req.ctx.uuid,
      org_UUID: await orgRepo.getOrgUUID(req.ctx.org),
      org: result
    }
    const userRepo = req.ctx.repositories.getUserRepository()
    payload.user_UUID = await userRepo.getUserUUID(req.ctx.user, payload.org_UUID)
    logger.info(JSON.stringify(payload))
    return res.status(200).json(responseMessage)
  } catch (err) {
    next(err)
  }
}

// Updates an org only if the org exist for the specified shortname. If no org exists, we do not create the org.
async function updateOrg (req, res, next) {
  try {
    const shortName = req.ctx.params.shortname
    const newOrg = new Org()
    const removeRoles = []
    const addRoles = []
    const orgRepo = req.ctx.repositories.getOrgRepository()
    const org = await orgRepo.findOneByShortName(shortName)
    let agt = setAggregateOrgObj({ short_name: shortName })

    // org doesn't exist
    if (!org) {
      logger.info({ uuid: req.ctx.uuid, message: shortName + ' organization could not be updated in MongoDB because it does not exist.' })
      return res.status(404).json(error.orgDneParam(shortName))
    }

    Object.keys(req.ctx.query).forEach(k => {
      const key = k.toLowerCase()

      if (key === 'shortname') {
        newOrg.short_name = req.ctx.query.shortname
        agt = setAggregateOrgObj({ short_name: newOrg.short_name })
      } else if (key === 'name') {
        newOrg.name = req.ctx.query.name
      } else if (key === 'id_quota') {
        newOrg.policies.id_quota = req.ctx.query.id_quota
      } else if (key === 'active_roles.add') {
        if (Array.isArray(req.ctx.query['active_roles.add'])) {
          req.ctx.query['active_roles.add'].forEach(r => {
            addRoles.push(r)
          })
        }
      } else if (key === 'active_roles.remove') {
        if (Array.isArray(req.ctx.query['active_roles.remove'])) {
          req.ctx.query['active_roles.remove'].forEach(r => {
            removeRoles.push(r)
          })
        }
      }
    })

    // updating the org's roles
    if (org) {
      const roles = org.authority.active_roles

      // adding roles
      addRoles.forEach(role => {
        if (!roles.includes(role)) {
          roles.push(role)
        }
      })

      // removing roles
      removeRoles.forEach(role => {
        const index = roles.indexOf(role)

        if (index > -1) {
          roles.splice(index, 1)
        }
      })

      newOrg.authority.active_roles = roles
    }

    if (newOrg.short_name) {
      const result = await orgRepo.findOneByShortName(newOrg.short_name)

      if (result) {
        return res.status(403).json(error.duplicateShortname(newOrg.short_name))
      }
    }

    // update org
    let result = await orgRepo.updateByOrgUUID(org.UUID, newOrg)
    if (result.n === 0) {
      logger.info({ uuid: req.ctx.uuid, message: shortName + ' organization could not be updated in MongoDB because it does not exist.' })
      return res.status(404).json(error.orgDneParam(shortName))
    }

    result = await orgRepo.aggregate(agt)
    result = result.length > 0 ? result[0] : null

    const responseMessage = {
      message: shortName + ' organization was successfully updated.',
      updated: result
    }

    const payload = {
      action: 'update_org',
      change: shortName + ' organization was successfully updated.',
      req_UUID: req.ctx.uuid,
      org_UUID: await orgRepo.getOrgUUID(req.ctx.org),
      org: result
    }
    const userRepo = req.ctx.repositories.getUserRepository()
    payload.user_UUID = await userRepo.getUserUUID(req.ctx.user, payload.org_UUID)
    logger.info(JSON.stringify(payload))
    return res.status(200).json(responseMessage)
  } catch (err) {
    next(err)
  }
}

// Creates a user only if the org exist and the user does not exist for the specified shortname and username
async function createUser (req, res, next) {
  try {
    const orgShortName = req.ctx.params.shortname
    const requesterUsername = req.ctx.user
    const requesterShortName = req.ctx.org
    const orgRepo = req.ctx.repositories.getOrgRepository()
    const userRepo = req.ctx.repositories.getUserRepository()
    const newUser = new User()

    const orgUUID = await orgRepo.getOrgUUID(orgShortName)
    if (!orgUUID) { // the org can only be non-existent if the requestor is the Secretariat
      logger.info({ uuid: req.ctx.uuid, message: 'The user could not be created because ' + orgShortName + ' organization does not exist.' })
      return res.status(404).json(error.orgDneParam(orgShortName))
    }

    Object.keys(req.ctx.body).forEach(k => {
      const key = k.toLowerCase()

      if (key === 'username') {
        newUser.username = req.ctx.body.username
      } else if (key === 'authority') {
        if (req.ctx.body.authority.active_roles) {
          newUser.authority.active_roles = req.ctx.body.authority.active_roles
        }
      } else if (key === 'name') {
        if (req.ctx.body.name.first) {
          newUser.name.first = req.ctx.body.name.first
        }
        if (req.ctx.body.name.last) {
          newUser.name.last = req.ctx.body.name.last
        }
        if (req.ctx.body.name.middle) {
          newUser.name.middle = req.ctx.body.name.middle
        }
        if (req.ctx.body.name.suffix) {
          newUser.name.suffix = req.ctx.body.name.suffix
        }
      } else if (key === 'org_uuid') {
        return res.status(400).json(error.uuidProvided())
      } else if (key === 'uuid') {
        return res.status(400).json(error.uuidProvided())
      }
    })

    const requesterOrgUUID = await orgRepo.getOrgUUID(requesterShortName)
    const isSecretariat = await orgRepo.isSecretariatUUID(requesterOrgUUID)
    const isAdmin = await userRepo.isAdminUUID(requesterUsername, requesterOrgUUID)
    // check if user is only an Admin (not Secretatiat) and the user does not belong to the same organization as the new user
    if (!isSecretariat && isAdmin) {
      if (requesterOrgUUID !== orgUUID) {
        return res.status(403).json(error.notOrgAdminOrSecretariat()) // The Admin user must belong to the new user's organization
      }
    }

    newUser.org_UUID = orgUUID
    newUser.UUID = uuid.v4()
    newUser.active = true
    const randomKey = cryptoRandomString({ length: CONSTANTS.CRYPTO_RANDOM_STRING_LENGTH })
    newUser.secret = await argon2.hash(randomKey)

    let result = await userRepo.findOneByUserNameAndOrgUUID(newUser.username, newUser.org_UUID) // Find user in MongoDB
    if (result) {
      logger.info({ uuid: req.ctx.uuid, message: newUser.username + ' was not created because it already exists.' })
      return res.status(400).json(error.userExists(newUser.username))
    }

    // Parsing all user name fields
    newUser.name = parseUserName(newUser)

    await userRepo.updateByUserNameAndOrgUUID(newUser.username, newUser.org_UUID, newUser, { upsert: true }) // Create user in MongoDB if it doesn't exist
    const agt = setAggregateUserObj({ username: newUser.username, org_UUID: newUser.org_UUID })
    result = await userRepo.aggregate(agt)
    result = result.length > 0 ? result[0] : null

    result.secret = randomKey
    const responseMessage = {
      message: result.username + ' was successfully created.',
      created: result
    }

    const payload = {
      action: 'create_user',
      change: result.username + ' was successfully created.',
      req_UUID: req.ctx.uuid,
      org_UUID: await orgRepo.getOrgUUID(req.ctx.org),
      user: result
    }
    payload.user_UUID = await userRepo.getUserUUID(req.ctx.user, payload.org_UUID)
    logger.info(JSON.stringify(payload))
    return res.status(200).json(responseMessage)
  } catch (err) {
    next(err)
  }
}

// Updates a user only if the user exist for the specified username. If no user exists, it does not create the user.
async function updateUser (req, res, next) {
  try {
    const requesterShortName = req.ctx.org
    const requesterUsername = req.ctx.user
    const username = req.ctx.params.username
    const shortName = req.ctx.params.shortname
    const newUser = new User()
    let newOrgShortName
    let changesRequirePrivilegedRole // Set variable to true if protected fields are being modified
    const removeRoles = []
    const addRoles = []
    const userRepo = req.ctx.repositories.getUserRepository()
    const orgRepo = req.ctx.repositories.getOrgRepository()
    const orgUUID = await orgRepo.getOrgUUID(shortName)
    const isSecretariat = await orgRepo.isSecretariat(requesterShortName)
    const isAdmin = await userRepo.isAdmin(requesterUsername, requesterShortName) // Check if requester is Admin of the designated user's org

    if (!orgUUID) {
      logger.info({ uuid: req.ctx.uuid, message: 'The user could not be updated because ' + shortName + ' organization does not exist.' })
      return res.status(404).json(error.orgDneParam(shortName))
    }

    if (shortName !== requesterShortName && !isSecretariat) {
      logger.info({ uuid: req.ctx.uuid, message: shortName + ' organization can only be viewed by the users of the same organization or the Secretariat.' })
      return res.status(403).json(error.notSameOrgOrSecretariat())
    }

    const user = await userRepo.findOneByUserNameAndOrgUUID(username, orgUUID)
    if (!user) {
      logger.info({ uuid: req.ctx.uuid, message: 'The user could not be updated because ' + username + ' does not exist for ' + shortName + ' organization.' })
      return res.status(404).json(error.userDne(username))
    }

    // check if the user is not the requester or if the requester is not a secretariat
    if ((shortName !== requesterShortName || username !== requesterUsername) && !isSecretariat) {
      // check if the requester is not and admin; if admin, the requester must be from the same org as the user
      if (!isAdmin || (isAdmin && shortName !== requesterShortName)) {
        logger.info({ uuid: req.ctx.uuid, message: 'The user can only be updated by the Secretariat, an Org admin or if the requester is the user.' })
        return res.status(403).json(error.notSameUserOrSecretariat())
      }
    }

    Object.keys(req.ctx.query).forEach(k => {
      const key = k.toLowerCase()

      if (key === 'new_username') {
        newUser.username = req.ctx.query.new_username
      } else if (key === 'org_shortname') {
        newOrgShortName = req.ctx.query.org_shortname
        changesRequirePrivilegedRole = true
      } else if (key === 'name.first') {
        newUser.name.first = req.ctx.query['name.first']
      } else if (key === 'name.last') {
        newUser.name.last = req.ctx.query['name.last']
      } else if (key === 'name.middle') {
        newUser.name.middle = req.ctx.query['name.middle']
      } else if (key === 'name.suffix') {
        newUser.name.suffix = req.ctx.query['name.suffix']
      } else if (key === 'active') {
        newUser.active = req.ctx.query.active
        changesRequirePrivilegedRole = true
      } else if (key === 'active_roles.add') {
        if (Array.isArray(req.ctx.query['active_roles.add'])) {
          req.ctx.query['active_roles.add'].forEach(r => {
            addRoles.push(r)
          })
          changesRequirePrivilegedRole = true
        }
      } else if (key === 'active_roles.remove') {
        if (Array.isArray(req.ctx.query['active_roles.remove'])) {
          req.ctx.query['active_roles.remove'].forEach(r => {
            removeRoles.push(r)
          })
          changesRequirePrivilegedRole = true
        }
      }
    })

    // updating user's roles and org_uuid is only allowed for secretariats and org admins
    if (changesRequirePrivilegedRole && !(isAdmin || isSecretariat)) {
      logger.info({ uuid: req.ctx.uuid, message: 'The user could not be updated because ' + requesterUsername + ' user is not Org Admin or Secretariat to modify these fields.' })
      return res.status(403).json(error.notOrgAdminOrSecretariat())
    }

    // check if the new org exist
    if (newOrgShortName) {
      newUser.org_UUID = await orgRepo.getOrgUUID(newOrgShortName)

      if (!newUser.org_UUID) {
        logger.info({ uuid: req.ctx.uuid, message: 'The user could not be updated because ' + newOrgShortName + ' organization does not exist.' })
        return res.status(404).json(error.orgDne(newOrgShortName))
      }
    }

    let agt = setAggregateUserObj({ username: username, org_UUID: orgUUID })

    // check if org has user of same username already
    if (newUser.username && newUser.org_UUID) {
      agt = setAggregateUserObj({ username: newUser.username, org_UUID: newUser.org_UUID })
      const duplicateUsers = await userRepo.find({ org_UUID: newUser.org_UUID, username: newUser.username })
      if (duplicateUsers.length) {
        logger.info({ uuid: req.ctx.uuid, message: 'The user could not be updated because ' + newOrgShortName + ' organization contains a user with the same username.' })
        return res.status(403).json(error.duplicateUsername(newOrgShortName, newUser.username))
      }
    } else if (newUser.username) {
      agt = setAggregateUserObj({ username: newUser.username, org_UUID: orgUUID })
      const duplicateUsers = await userRepo.find({ org_UUID: orgUUID, username: newUser.username })
      if (duplicateUsers.length) {
        logger.info({ uuid: req.ctx.uuid, message: 'The user could not be updated because ' + shortName + ' organization contains a user with the same username.' })
        return res.status(403).json(error.duplicateUsername(shortName, newUser.username))
      }
    } else if (newUser.org_UUID) {
      agt = setAggregateUserObj({ username: username, org_UUID: newUser.org_UUID })
      const duplicateUsers = await userRepo.find({ org_UUID: newUser.org_UUID, username: username })
      if (duplicateUsers.length) {
        logger.info({ uuid: req.ctx.uuid, message: 'The user could not be updated because ' + newOrgShortName + ' organization contains a user with the same username.' })
        return res.status(403).json(error.duplicateUsername(newOrgShortName, username))
      }
    }

    // updating the user's roles
    const roles = user.authority.active_roles

    // adding roles
    addRoles.forEach(role => {
      if (!roles.includes(role)) {
        roles.push(role)
      }
    })

    // removing roles
    removeRoles.forEach(role => {
      const index = roles.indexOf(role)

      if (index > -1) {
        roles.splice(index, 1)
      }
    })

    newUser.authority.active_roles = roles

    let result = await userRepo.updateByUserNameAndOrgUUID(username, orgUUID, newUser)
    if (result.n === 0) {
      logger.info({ uuid: req.ctx.uuid, message: 'The user could not be updated because ' + username + ' does not exist for ' + shortName + ' organization.' })
      return res.status(404).json(error.userDne(username))
    }

    result = await userRepo.aggregate(agt)
    result = result.length > 0 ? result[0] : null

    const responseMessage = {
      message: username + ' was successfully updated.',
      updated: result
    }

    const payload = {
      action: 'update_user',
      change: username + ' was successfully updated.',
      req_UUID: req.ctx.uuid,
      org_UUID: await orgRepo.getOrgUUID(req.ctx.org),
      user: result
    }
    payload.user_UUID = await userRepo.getUserUUID(req.ctx.user, payload.org_UUID)
    logger.info(JSON.stringify(payload))
    return res.status(200).json(responseMessage)
  } catch (err) {
    next(err)
  }
}

async function resetSecret (req, res, next) {
  try {
    const requesterShortName = req.ctx.org
    const requesterUsername = req.ctx.user
    const username = req.ctx.params.username
    const orgShortName = req.ctx.params.shortname
    const userRepo = req.ctx.repositories.getUserRepository()
    const orgRepo = req.ctx.repositories.getOrgRepository()
    const isSecretariat = await orgRepo.isSecretariat(requesterShortName)
    const orgUUID = await orgRepo.getOrgUUID(orgShortName) // userUUID may be null if user does not exist
    if (!orgUUID) {
      logger.info({ uuid: req.ctx.uuid, messsage: orgShortName + ' organization does not exist.' })
      return res.status(404).json(error.orgDneParam(orgShortName))
    }

    if (orgShortName !== requesterShortName && !isSecretariat) {
      logger.info({ uuid: req.ctx.uuid, message: orgShortName + ' organization can only be viewed by the users of the same organization or the Secretariat.' })
      return res.status(403).json(error.notSameOrgOrSecretariat())
    }

    const oldUser = await userRepo.findOneByUserNameAndOrgUUID(username, orgUUID)
    if (!oldUser) {
      logger.info({ uuid: req.ctx.uuid, messsage: username + ' user does not exist.' })
      return res.status(404).json(error.userDne(username))
    }

    const isAdmin = await userRepo.isAdmin(requesterUsername, requesterShortName)
    // check if the user is not the requester or if the requester is not a secretariat
    if ((orgShortName !== requesterShortName || username !== requesterUsername) && !isSecretariat) {
      // check if the requester is not and admin; if admin, the requester must be from the same org as the user
      if (!isAdmin || (isAdmin && orgShortName !== requesterShortName)) {
        logger.info({ uuid: req.ctx.uuid, message: 'The api secret can only be reset by the Secretariat, an Org admin or if the requester is the user.' })
        return res.status(403).json(error.notSameUserOrSecretariat())
      }
    }

    const randomKey = cryptoRandomString({ length: CONSTANTS.CRYPTO_RANDOM_STRING_LENGTH })
    oldUser.secret = await argon2.hash(randomKey) // store in db
    const user = await userRepo.updateByUserNameAndOrgUUID(oldUser.username, orgUUID, oldUser)
    if (user.n === 0) {
      logger.info({ uuid: req.ctx.uuid, message: 'The user could not be updated because ' + username + ' does not exist for ' + orgShortName + ' organization.' })
      return res.status(404).json(error.userDne(username))
    }

    logger.info({ uuid: req.ctx.uuid, message: `The API secret was successfully reset and sent to ${username}` })
    const payload = {
      action: 'reset_userAPIkey',
      change: 'API secret was successfully reset.',
      req_UUID: req.ctx.uuid,
      org_UUID: await orgRepo.getOrgUUID(req.ctx.org)
    }
    payload.user_UUID = await userRepo.getUserUUID(req.ctx.user, payload.org_UUID)
    logger.info(JSON.stringify(payload))
    return res.status(200).json({ 'API-secret': randomKey })
  } catch (err) {
    next(err)
  }
}

function setAggregateOrgObj (query) {
  return [
    {
      $match: query
    },
    {
      $project: {
        _id: false,
        UUID: true,
        short_name: true,
        name: true,
        'authority.active_roles': true,
        'policies.id_quota': true,
        time: true
      }
    }
  ]
}

function setAggregateUserObj (query) {
  return [
    {
      $match: query
    },
    {
      $project: {
        _id: false,
        username: true,
        name: true,
        UUID: true,
        org_UUID: true,
        active: true,
        'authority.active_roles': true,
        time: true
      }
    }
  ]
}

function parseUserName (newUser) {
  if (newUser.name) {
    if (!newUser.name.first) {
      newUser.name.first = ''
    }
    if (!newUser.name.last) {
      newUser.name.last = ''
    }
    if (!newUser.name.middle) {
      newUser.name.middle = ''
    }
    if (!newUser.name.suffix) {
      newUser.name.suffix = ''
    }
  }

  return newUser.name
}

module.exports = {
  ORG_ALL: getOrgs,
  ORG_SINGLE: getOrg,
  ORG_CREATE_SINGLE: createOrg,
  ORG_UPDATE_SINGLE: updateOrg,
  USER_ALL: getUsers,
  ORG_ID_QUOTA: getOrgIdQuota,
  USER_SINGLE: getUser,
  USER_CREATE_SINGLE: createUser,
  USER_UPDATE_SINGLE: updateUser,
  USER_RESET_SECRET: resetSecret
}
