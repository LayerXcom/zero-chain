FROM phusion/baseimage:0.11 as builder
LABEL maintainer="osuke.sudo@layerx.co.jp"
LABEL description="This is the build stage for Zerochain. Here we create the binary."

ARG PROFILE=release
WORKDIR /zerochain

COPY . /zerochain

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y cmake pkg-config libssl-dev git clang

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y && \
    export PATH="$PATH:$HOME/.cargo/bin" && \
    rustup toolchain install nightly && \
    rustup target add wasm32-unknown-unknown --toolchain nightly && \
    cargo install --git https://github.com/alexcrichton/wasm-gc && \
    rustup default nightly && \
    ./build.sh && \
    rustup default stable && \
    cargo build --$PROFILE --all

# ===== SECOND STAGE ======

FROM phusion/baseimage:0.11
LABEL maintainer="osuke.sudo@layerx.co.jp"
LABEL description="This is the 2nd stage: a very small image where we copy the Zerochain binary."
ARG PROFILE=release

COPY --from=builder /zerochain/target/$PROFILE/zerochain /usr/local/bin
COPY --from=builder /zerochain/zface/verification.params /usr/local/bin/zface/verification.params

RUN rm -rf /usr/lib/python* && \
    mkdir -p /root/.local/share && \
    ln -s /root/.local/share /data

EXPOSE 30333 9933 9944
VOLUME ["/data"]

WORKDIR /usr/local/bin
CMD ["zerochain", "--dev", "--ws-external"]