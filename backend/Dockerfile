# syntax=docker/dockerfile:1

FROM alpine:3.20 AS prowler-data
RUN apk add --no-cache git ca-certificates
ARG PROWLER_REPO=https://github.com/prowler-cloud/prowler.git
ARG PROWLER_REF=master
# BuildKit rechecks this git ref and rebuilds the catalog when the commit moves.
ADD --keep-git-dir=true ${PROWLER_REPO}#${PROWLER_REF} /src
COPY fetch-prowler-data.sh /tmp/fetch-prowler-data.sh
RUN sh /tmp/fetch-prowler-data.sh /src /out

FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js auth.js reset-password.js review.js agent.js ./
ENV NODE_ENV=production
COPY --from=prowler-data /out/compliance /compliance
COPY --from=prowler-data /out/check-metadata /check-metadata
COPY --from=prowler-data /out/catalog.json /prowler-catalog.json
RUN mkdir -p /data/projects
VOLUME ["/data"]
EXPOSE 3001
CMD ["node", "server.js"]
