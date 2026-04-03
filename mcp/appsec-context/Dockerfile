FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY index.js ./

# MCP servers communicate over stdio — keep the container's stdin open
ENTRYPOINT ["node", "index.js"]
