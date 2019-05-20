FROM node:boron-alpine
MAINTAINER butlerx <butlerx@notthe.cloud>

RUN apk add --update git build-base python &&\
    mkdir -p /usr/src/app
WORKDIR /usr/src/app
ADD . /usr/src/app/
RUN yarn --ignore-engines && \
    apk del build-base python && \
    rm -rf /tmp/* /root/.npm /root/.node-gyp
EXPOSE  80
ENTRYPOINT ["node", "app"]
