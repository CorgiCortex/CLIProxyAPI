FROM node:24-bookworm
WORKDIR /app
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npx playwright install --with-deps chromium && chmod -R a+rX /ms-playwright
COPY server.mjs pool.mjs ./
ENV PORT=8318
CMD ["node", "server.mjs"]
