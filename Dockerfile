FROM --platform=$TARGETPLATFORM rust as builder
RUN apt update
RUN apt install python3 python3-pip -y
RUN pip install maturin

WORKDIR /build
COPY . .
RUN make py

FROM jupyter/minimal-notebook:aarch64-python-3.10.5 as branch-arm64
ENV ARCHITECTURE="arm64"
FROM jupyter/minimal-notebook:python-3.10.5 as branch-amd64
ENV ARCHITECTURE="amd64"

FROM branch-${TARGETARCH}
RUN echo ${ARCHITECTURE}
COPY --from=builder /build/coeus-python/target/wheels/*.whl /tmp/wheels/
USER root
RUN python3 -m pip install ipywidgets
RUN for pkg in $(ls /tmp/wheels); do python3 -m pip install /tmp/wheels/$pkg; done
RUN jupyter nbextension install --py widgetsnbextension
RUN jupyter nbextension enable widgetsnbextension --py

USER ${NB_UID}