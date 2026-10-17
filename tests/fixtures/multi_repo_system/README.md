# Combined assessment fixture

Three small services form one system. `storefront` is a browser client that calls the `orders-api` HTTP service. `orders-api` stores orders in SQLite and publishes an `order-created` message to an AMQP broker. `fulfillment-worker` consumes that message and writes a shipping label file. Each directory becomes its own Git checkout; see `docs/internal/runbooks/e2e-multi-repo-fixture.md`.

The code contains deliberate weaknesses for the acceptance run. Do not deploy it.
