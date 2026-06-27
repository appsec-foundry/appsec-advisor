module.exports = async (req, res, next) => {
  const partnerApiKey = req.headers['x-partner-api-key']
  if (!partnerApiKey) return res.status(401).json({ error: 'Partner API key required' })
  const partner = await db.partners.findByApiKey(partnerApiKey)
  if (!partner) return res.status(403).json({ error: 'Invalid partner key' })
  req.partner = partner
  next()
}
