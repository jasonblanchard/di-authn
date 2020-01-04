FROM node:12.14.0-buster AS base

ENV APP_HOME /usr/src/app/
ENV PROD_DEPS /usr/src/deps/prod/
RUN useradd -ms /bin/bash docker

FROM base AS build

USER docker

COPY --chown=docker:docker package.json package-lock.json $PROD_DEPS
WORKDIR $PROD_DEPS
RUN npm ci --production

COPY --chown=docker:docker package.json package-lock.json $APP_HOME
WORKDIR $APP_HOME
RUN npm ci

COPY --chown=docker:docker src $APP_HOME/src/
COPY --chown=docker:docker tsconfig.json $APP_HOME/

WORKDIR $APP_HOME
RUN npm run build

FROM base AS release

USER docker
WORKDIR $APP_HOME
COPY --from=build --chown=docker:docker $PROD_DEPS/node_modules $APP_HOME/node_modules/
COPY --from=build --chown=docker:docker $APP_HOME/build $APP_HOME/build
COPY --from=build --chown=docker:docker $APP_HOME/package.json $APP_HOME/package.json

EXPOSE 4000

CMD ["npm", "start", "--production"]
