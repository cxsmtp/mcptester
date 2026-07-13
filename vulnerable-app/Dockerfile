# IaC misconfigurations for Checkmarx KICS. Intentionally insecure.
FROM node:8                             # KICS: outdated/untrusted base, no digest pin

# Runs as root (no USER directive)
ENV DB_PASSWORD=Sup3rS3cr3tR00tP@ss!    # KICS: secret in ENV / image layer
ENV NODE_TLS_REJECT_UNAUTHORIZED=0      # disables TLS verification

WORKDIR /app
COPY . .                                # copies .env and secrets into the image
RUN npm install                         # installs vulnerable deps, no --production, no audit

# curl | bash anti-pattern
RUN apt-get update && apt-get install -y curl \
    && curl -sL http://example.com/install.sh | bash

EXPOSE 3000
# No HEALTHCHECK, no USER, runs as root
CMD ["node", "src/app.js"]
