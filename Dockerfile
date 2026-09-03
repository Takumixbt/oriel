FROM node:22-alpine

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=optional
COPY agent ./agent
COPY targets ./targets
COPY test-packs ./test-packs
COPY tsconfig.json ./

ENV ORIEL_TARGET_BIND=0.0.0.0
ENV ORIEL_TARGET_PORT=8787
EXPOSE 8787

CMD ["npm", "run", "targets"]
