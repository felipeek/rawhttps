# Use an official base image with build tools available
FROM --platform=linux/amd64 debian:buster

# Install necessary packages
RUN apt-get update && \
    apt-get install -y build-essential gcc make nasm curl

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the entire project into the container
COPY . .

RUN rm -r bin

# Compile the library using the Makefile
RUN make

# Compile the app binary
RUN gcc main.c bin/rawhttps.a -o main -lpthread

# Set up the entrypoint to run the binary
# Assuming the certificates are named cert.crt and cert.key in the current directory
ENTRYPOINT ["./main", "cert.crt", "cert.key"]

# Instructions to mount certificates at runtime using Docker volumes:
# docker run -v ~/Development/openssl_certificate_generation/local-deployer/client1.crt:/usr/src/app/cert.crt \
#            -v ~/Development/openssl_certificate_generation/local-deployer/client1.key:/usr/src/app/cert.key \
#            your_image_name
