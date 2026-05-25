// B2B Partner API — Order management endpoint
// Only accessible to authenticated B2B partners
const express = require('express')
const router = express.Router()
const partnerAuth = require('../../middleware/partnerAuth')

router.use(partnerAuth)

// Partners can query orders for their own accounts only
router.get('/orders', async (req, res) => {
  const orders = await db.orders.findByPartnerId(req.partner.id)
  res.json(orders)
})

router.post('/orders', async (req, res) => {
  const order = await db.orders.create({ ...req.body, partner_id: req.partner.id })
  res.status(201).json(order)
})

module.exports = router
