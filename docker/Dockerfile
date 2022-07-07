FROM node:16.14.2-alpine3.15

LABEL \
    mitre.name=cveawg \
    mitre.project=cveawg \
    mitre.maintainer=mbianchi@mitre.org


# Install python/pip (required for argon2 build from source)
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools

# Install build essentials (also required for argon2)
RUN apk add --update --no-cache build-base

# Set up directory to run as node user rather than root
ADD . /home/node/app
RUN rm -Rf /home/node/app/.git # we don't need this
RUN chown -R node:node /home/node

WORKDIR /home/node/app

RUN npm install --production
COPY --chown=node:node docker/entrypoint.sh /home/node/app/entrypoint.sh
RUN echo '{}' > /home/node/app/config/dev.json
RUN echo '{}' > /home/node/app/config/test.json
RUN echo '{}' > /home/node/app/config/staging.json

# Change db hostname from localhost to docdb for use inside docker
COPY docker/default.json-docker /home/node/app/config/default.json

# Run as the node user rather than root
USER node
EXPOSE 3000
ENTRYPOINT '/home/node/app/entrypoint.sh'
