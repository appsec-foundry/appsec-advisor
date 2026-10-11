import { ORDERS_API } from "./config.js";

export async function showOrders(customerId) {
  const response = await fetch(`${ORDERS_API}/api/orders?customer=${customerId}`);
  const orders = await response.json();
  const list = document.getElementById("orders");
  // Order notes come from other customers' input and are inserted as HTML.
  list.innerHTML = orders.map((o) => `<li>${o.item}: ${o.note}</li>`).join("");
}

export async function placeOrder(customerId, item, note) {
  await fetch(`${ORDERS_API}/api/orders`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ customer: customerId, item, note }),
  });
}
