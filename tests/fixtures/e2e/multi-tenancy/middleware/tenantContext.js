// Tenant scoping middleware — sets current_tenant on every request
module.exports = async (req, res, next) => {
  const tenantId = req.headers['x-tenant-id']
  if (!tenantId) return res.status(400).json({ error: 'Missing tenant' })

  // Attach tenant context so downstream handlers can scope queries
  req.tenantContext = { tenant_id: tenantId }
  next()
}
