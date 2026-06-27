module.exports = (req, res, next) => {
  const tenantId = req.headers['x-tenant-id']
  if (!tenantId) return res.status(400).json({ error: 'Missing tenant' })
  req.tenantContext = { tenant_id: tenantId }
  next()
}
