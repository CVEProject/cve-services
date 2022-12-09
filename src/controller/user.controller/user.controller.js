require('dotenv').config()
const logger = require('../../middleware/logger')
const getConstants = require('../../constants').getConstants

/**
 * Get the details of all users
 * Called by GET /api/users
**/
async function getAllUsers (req, res, next) {
  try {
    const CONSTANTS = getConstants()

    // temporary measure to allow tests to work after fixing #920
    // tests required changing the global limit to force pagination
    if (req.TEST_PAGINATOR_LIMIT) {
      CONSTANTS.PAGINATOR_OPTIONS.limit = req.TEST_PAGINATOR_LIMIT
    }

    const options = CONSTANTS.PAGINATOR_OPTIONS
    options.sort = { short_name: 'asc' }
    options.page = req.ctx.query.page ? parseInt(req.ctx.query.page) : CONSTANTS.PAGINATOR_PAGE // if 'page' query parameter is not defined, set 'page' to the default page value
    const repo = req.ctx.repositories.getUserRepository()

    const agt = setAggregateUserObj({})
    const pg = await repo.aggregatePaginate(agt, options)
    const payload = { users: pg.itemsList }

    if (pg.itemCount >= CONSTANTS.PAGINATOR_OPTIONS.limit) {
      payload.totalCount = pg.itemCount
      payload.itemsPerPage = pg.itemsPerPage
      payload.pageCount = pg.pageCount
      payload.currentPage = pg.currentPage
      payload.prevPage = pg.prevPage
      payload.nextPage = pg.nextPage
    }

    logger.info({ uuid: req.ctx.uuid, message: 'The user information was sent to the secretariat user.' })
    return res.status(200).json(payload)
  } catch (err) {
    next(err)
  }
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

module.exports = {
  ALL_USERS: getAllUsers
}
