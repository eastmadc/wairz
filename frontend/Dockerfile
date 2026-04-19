# Build stage
FROM node:20-slim AS build
WORKDIR /app
# Optional: API key baked into the static bundle at build time.
# Local dev sets this via docker-compose.override.yml; production should
# either bake a strong key here OR leave empty and rely on runtime
# localStorage (see src/api/client.ts::getApiKey).
ARG VITE_API_KEY=""
ENV VITE_API_KEY=${VITE_API_KEY}
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine
ENV MAX_UPLOAD_SIZE_MB=2048
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
EXPOSE 3000
CMD ["nginx", "-g", "daemon off;"]
