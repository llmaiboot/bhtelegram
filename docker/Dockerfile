FROM ghcr.io/ombra-chat/builder:v0.0.6 AS builder-stage

RUN git clone https://github.com/ombra-chat/tdlib-rs.git
RUN git clone https://github.com/llmaiboot/bhtelegram.git

RUN cd tdlib-rs && git checkout 7c6972dd2d2aa2fcd62dc9660682c9bac2a12c39

WORKDIR /bhtelegram

ARG TAG=master
RUN git checkout $TAG

# See https://github.com/linuxdeploy/linuxdeploy/issues/154
ENV APPIMAGE_EXTRACT_AND_RUN=1

RUN bash -c "source $HOME/.nvm/nvm.sh && source $HOME/.cargo/env && npm install && npm run tauri build"

RUN lib_name=$(ls /usr/lib/libtdjson.so.* | sed -E "s|(.*).so|\1-`uname -m`.so|") && mv /usr/lib/libtdjson.so.* "${lib_name}"

FROM scratch
COPY --from=builder-stage /bhtelegram/src-tauri/target/release/bundle/deb/bhtelegram*.deb /
COPY --from=builder-stage /bhtelegram/src-tauri/target/release/bundle/rpm/bhtelegram*.rpm /
COPY --from=builder-stage /bhtelegram/src-tauri/target/release/bundle/appimage/bhtelegram*.AppImage /
COPY --from=builder-stage /usr/lib/libtdjson-*.so.* /
