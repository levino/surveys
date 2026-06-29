# syntax=docker/dockerfile:1

# --- Stage 1: build the Tailwind + DaisyUI stylesheet (self-hosted, no CDN) ---
FROM node:22-bookworm-slim AS css
WORKDIR /src
COPY package.json package-lock.json tailwind.config.js ./
RUN npm ci --no-audit --no-fund
COPY assets/input.css ./assets/input.css
COPY ui ./ui
RUN npm run build:css   # scans ui/**/*.templ → minified assets/app.css

# --- Stage 2: cross-compile a static, CGO-free binary (embeds app.css) ---
# Runs natively on the BUILD platform and cross-compiles to TARGETARCH.
FROM --platform=$BUILDPLATFORM golang:1.23-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# The generated CSS is not committed; pull it from the css stage before building.
COPY --from=css /src/assets/app.css ./assets/app.css
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -trimpath -o /out/surveys .

# --- Stage 3: minimal runtime ---
FROM gcr.io/distroless/static-debian12:nonroot

ENV PORT=8080 \
    DATABASE_PATH=/data/app.db

COPY --from=build /out/surveys /surveys

VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/surveys"]
