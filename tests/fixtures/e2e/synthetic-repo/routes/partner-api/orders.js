const express = require('express')
const partnerAuth = require('../../middleware/partnerAuth')

const router = express.Router()
router.use(partnerAuth)
router.get('/orders', async (req, res) => {
  const orders = await db.orders.findByPartnerId(req.partner.id)
  res.json(orders)
})

module.exports = router
