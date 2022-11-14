const swaggerUi = require('swagger-ui-express')
const openApiSpecification = require('../api-docs/openapi.json')

const CveController = require('./controller/cve.controller')
const OrgController = require('./controller/org.controller')
const CveIdController = require('./controller/cve-id.controller')
const SchemasController = require('./controller/schemas.controller')
const SystemController = require('./controller/system.controller')
const UserController = require('./controller/user.controller')

var options = {
  swaggerOptions: {
    url: '/api-docs/openapi.json'
  }
}

// Hide try-out related elements and update some parameter display CSS
var setupOptions = {
  customCss: `.swagger-ui .try-out { display: none }
              .swagger-ui .parameters-col_description input { display: none }
              .swagger-ui .parameters-col_description select { display: none }              
              .swagger-ui .parameter__in { font-weight: bold; color: black }
              .swagger-ui .parameters-col_name { width: 20% }
              .swagger-ui .renderedMarkdown a {text-decoration: none;}`
}

module.exports = async function configureRoutes (app) {
  app.use('/api/', CveController)
  app.use('/api/', OrgController)
  app.use('/api/', CveIdController)
  app.use('/api/', SystemController)
  app.use('/api/', UserController)
  app.get('/api-docs/openapi.json', (req, res) => res.json(openApiSpecification))
  app.use('/api-docs', swaggerUi.serveFiles(null, options), swaggerUi.setup(null, setupOptions))
  app.use('/schemas/', SchemasController)
}
