# TOTM Trust API + PILA verifier in one image (Railway builds this automatically when it finds the Dockerfile).
# Stage 1 builds pila-verifier (PILA's Go SDK); stage 2 is the Node API, which starts it as a child process.

FROM golang:1.24-bookworm AS pila
WORKDIR /src
COPY pila-verifier/go.mod pila-verifier/go.sum ./
RUN go mod download
COPY pila-verifier/ ./
RUN go mod tidy && go build -trimpath -ldflags="-s -w" -o /out/pila-verifier .

FROM node:22-bookworm-slim
# Go uses the system CA store for HTTPS (NDAKey, PILA's DID resolver).
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src ./src
COPY contract ./contract
COPY --from=pila /out/pila-verifier ./bin/pila-verifier
USER node
CMD ["node", "src/index.js"]
