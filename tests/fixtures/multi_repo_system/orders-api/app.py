import json
import sqlite3

import pika
from flask import Flask, jsonify, request

app = Flask(__name__)
BROKER_URL = "amqp://broker.shop.svc.cluster.local:5672/orders"
QUEUE = "order-created"


def db():
    return sqlite3.connect("/data/orders.db")


@app.get("/api/orders")
def list_orders():
    customer = request.args["customer"]
    # The customer parameter is concatenated into SQL and no caller identity is checked.
    rows = db().execute("SELECT item, note FROM orders WHERE customer = '" + customer + "'").fetchall()
    return jsonify([{"item": item, "note": note} for item, note in rows])


@app.post("/api/orders")
def create_order():
    order = request.get_json()
    connection = db()
    connection.execute(
        "INSERT INTO orders (customer, item, note) VALUES (?, ?, ?)",
        (order["customer"], order["item"], order["note"]),
    )
    connection.commit()
    channel = pika.BlockingConnection(pika.URLParameters(BROKER_URL)).channel()
    channel.queue_declare(queue=QUEUE)
    channel.basic_publish(exchange="", routing_key=QUEUE, body=json.dumps(order))
    return jsonify({"status": "created"}), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
