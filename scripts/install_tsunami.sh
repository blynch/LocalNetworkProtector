#!/bin/bash
set -e

# Configuration
REPO_URL="https://github.com/google/tsunami-security-scanner.git"
PLUGINS_REPO_URL="https://github.com/google/tsunami-security-scanner-plugins.git"
IMAGE_TAG="localnetworkprotector/tsunami"
BUILD_DIR="tsunami_build"

echo "Checking for Docker..."
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed or not in PATH."
    echo "Please install Docker on this system (e.g. Raspberry Pi) before running this script."
    exit 1
fi

echo "Cleaning up previous build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "Cloning Tsunami repositories..."
git clone --depth 1 "$REPO_URL" "$BUILD_DIR/tsunami-security-scanner"
git clone --depth 1 "$PLUGINS_REPO_URL" "$BUILD_DIR/tsunami-security-scanner-plugins"

echo "Building Tsunami Docker image..."
# Based on Tsunami's quick_start.sh but adapted for local build
# We use the generic Dockerfile which should query architecture from base image (openjdk)
# Instructions suggest just running execution, but to have a local image we need to build it.

# Google provides 'google/tsunami-security-scanner' on Docker Hub but sometimes it's better to build locally for ARM/RPi if multi-arch manifest isn't perfect.
# However, let's try to pull first. If it works for ARM64, great.
# The user asked to "run a setup script to build the docker files". So we MUST build.

cd "$BUILD_DIR/tsunami-security-scanner"

# Copy plugins to a place where Dockerfile can see them if needed, or follow their standard build doc.
# Their quick_start.sh basically runs a pre-built image. 
# To build from source:
# ./gradlew dockerBuild -PdockerImageName=$IMAGE_TAG

echo "Building Tsunami Docker image using full.Dockerfile..."
# Tsunami repo usually contains Dockerfiles in the root since recent versions.
# We will try to build using the 'full.Dockerfile' which includes plugins.

if [ -f "full.Dockerfile" ]; then
    docker build -t "$IMAGE_TAG" -f full.Dockerfile .
elif [ -f "Dockerfile" ]; then
    docker build -t "$IMAGE_TAG" .
else
    echo "ERROR: No Dockerfile found in $(pwd). Cannot build Tsunami."
    exit 1
fi

echo "Build complete. Image tagged as $IMAGE_TAG"

# Clean up
cd ../..
rm -rf "$BUILD_DIR"

echo "Tsunami scanner image is ready."
