import json
import os

import pika

BROKER_URL = "amqp://broker.shop.svc.cluster.local:5672/orders"
QUEUE = "order-created"
LABEL_DIR = "/var/labels"


def handle(channel, method, properties, body):
    order = json.loads(body)
    # The item name from the message selects the label path without normalization.
    path = os.path.join(LABEL_DIR, order["item"] + ".txt")
    with open(path, "w", encoding="utf-8") as label:
        label.write(f"Ship {order['item']} to customer {order['customer']}\n")
    channel.basic_ack(delivery_tag=method.delivery_tag)


def main():
    channel = pika.BlockingConnection(pika.URLParameters(BROKER_URL)).channel()
    channel.queue_declare(queue=QUEUE)
    channel.basic_consume(queue=QUEUE, on_message_callback=handle)
    channel.start_consuming()


if __name__ == "__main__":
    main()
