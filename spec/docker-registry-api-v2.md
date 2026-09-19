# Registry API 2

> **Vendored reference.** Source: <https://docs.docker.com/reference/api/registry/latest.md>
> Fetched 2026-09-19. Docker Hub's supported subset of the Registry HTTP API V2 —
> the de-facto companion to the OCI Distribution Spec (bearer-token auth flow, pull/push/delete
> worked examples). For the complete protocol, see [`../distribution-spec/spec.md`](../distribution-spec/spec.md).

[API catalog](https://docs.docker.com/reference/api/) · [Registry overview](https://docs.docker.com/reference/api/registry/latest/) · [OpenAPI specification](https://docs.docker.com/reference/api/registry/latest.yaml)

API version: 2

## Overview

Docker Hub is an OCI-compliant registry, which means it adheres to the open
standards defined by the Open Container Initiative (OCI) for distributing
container images. This ensures compatibility with a wide range of tools and
platforms in the container ecosystem.

This reference documents the Docker Hub-supported subset of the Registry HTTP API V2.
It focuses on pulling, pushing, and deleting images. It does not cover the full OCI Distribution Specification.

For the complete OCI specification, see [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec).

## Connecting to the Registry API

### registryToken

Follow the WWW-Authenticate challenge and obtain a repository-scoped registry bearer token. Public image pulls can obtain a token without account credentials; the registry request still sends that token. This token exchange is separate from Hub API authentication.

Server: `https://registry-1.docker.io`

- [Registry authentication](https://docs.docker.com/reference/api/registry/auth/)

## Overview

All endpoints in this API are prefixed by the version and repository name, for example:

```
/v2/<name>/
```

This format provides structured access control and URI-based scoping of image operations.

For example, to interact with the `library/ubuntu` repository, use:

```
/v2/library/ubuntu/
```

Repository names must meet these requirements:
1. Consist of path components matching `[a-z0-9]+(?:[._-][a-z0-9]+)*`
2. If more than one component, they must be separated by `/`
3. Full repository name must be fewer than 256 characters

## Authentication

Specifies registry authentication.

## Manifests

Image manifests are JSON documents that describe an image: its configuration blob, the digests of each layer blob, and metadata such as media-types and annotations.

## Blobs

Blobs are the binary objects referenced from manifests:
the config JSON and one or more compressed layer tarballs.

## Pulling Images

Pulling an image involves retrieving the manifest and downloading each of the image's layer blobs. This section outlines the general steps followed by a working example.

1. [Get a bearer token for the repository](https://docs.docker.com/reference/api/registry/auth/).
2. [Get the image manifest](https://docs.docker.com/reference/api/registry/latest/operations/GetImageManifest/).
3. If the response in the previous step is a multi-architecture manifest list, you must do the following:
   - Parse the `manifests[]` array to locate the digest for your target platform (e.g., `linux/amd64`).
   - [Get the image manifest](https://docs.docker.com/reference/api/registry/latest/operations/GetImageManifest/) using the located digest.
4. [Check if the blob exists](https://docs.docker.com/reference/api/registry/latest/operations/CheckBlobExists/) before downloading. The client should send a `HEAD` request for each layer digest.
5. [Download each layer blob](https://docs.docker.com/reference/api/registry/latest/operations/GetBlob/) using the digest obtained from the manifest. The client should send a `GET` request for each layer digest.

The following bash script example pulls `library/ubuntu:latest` from Docker Hub.

```bash
#!/bin/bash

# Step 1: Get a bearer token
TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/ubuntu:pull" | jq -r .token)

# Step 2: Get the image manifest. In this example, an image manifest list is returned.
curl -s -H "Authorization: Bearer $TOKEN" \
     -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
     https://registry-1.docker.io/v2/library/ubuntu/manifests/latest \
     -o manifest-list.json

# Step 3a: Parse the `manifests[]` array to locate the digest for your target platform (e.g., `linux/amd64`).
IMAGE_MANIFEST_DIGEST=$(jq -r '.manifests[] | select(.platform.architecture == "amd64" and .platform.os == "linux") | .digest' manifest-list.json)

# Step 3b: Get the platform-specific image manifest
curl -s -H "Authorization: Bearer $TOKEN" \
     -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
     https://registry-1.docker.io/v2/library/ubuntu/manifests/$IMAGE_MANIFEST_DIGEST \
     -o manifest.json

# Step 4: Send a HEAD request to check if the layer blob exists
DIGEST=$(jq -r '.layers[0].digest' manifest.json)
curl -I -H "Authorization: Bearer $TOKEN" \
     https://registry-1.docker.io/v2/library/ubuntu/blobs/$DIGEST

# Step 5: Download the layer blob
curl -L -H "Authorization: Bearer $TOKEN" \
     https://registry-1.docker.io/v2/library/ubuntu/blobs/$DIGEST
```

This example pulls the manifest and the first layer for the `ubuntu:latest` image on the `linux/amd64` platform. Repeat steps 4 and 5 for each digest in the `.layers[]` array in the manifest.

## Pushing Images

Pushing an image involves uploading any image blobs (such as the config or layers), and then uploading the manifest that references those blobs.

This section outlines the basic steps to push an image using the registry API.

1. [Get a bearer token for the repository](https://docs.docker.com/reference/api/registry/auth/)

2. [Check if the blob exists](https://docs.docker.com/reference/api/registry/latest/operations/CheckBlobExists/) using a `HEAD` request for each blob digest.

3. If the blob does not exist, [upload the blob](https://docs.docker.com/reference/api/registry/latest/operations/CompleteBlobUpload/) using a monolithic `PUT` request:
    - First, [initiate the upload](https://docs.docker.com/reference/api/registry/latest/operations/InitiateBlobUpload/) with `POST`.
    - Then [upload and complete](https://docs.docker.com/reference/api/registry/latest/operations/CompleteBlobUpload/) with `PUT`.

    **Note**:  Alternatively, you can upload the blob in multiple chunks by using `PATCH` requests to send each chunk, followed by a final `PUT` request to complete the upload. This is known as a [chunked upload](https://docs.docker.com/reference/api/registry/latest/operations/UploadBlobChunk/) and is useful for large blobs or when resuming interrupted uploads.

4. [Upload the image manifest](https://docs.docker.com/reference/api/registry/latest/operations/PutImageManifest/) using a `PUT` request to associate the config and layers.

The following bash script example pushes a dummy config blob and manifest to `yourusername/helloworld:latest` on Docker Hub. You can replace `yourusername` with your Docker Hub username and `dckr_pat` with your Docker Hub personal access token.

```bash
#!/bin/bash

USERNAME=yourusername
PASSWORD=dckr_pat
REPO=yourusername/helloworld
TAG=latest
CONFIG=config.json
MIME_TYPE=application/vnd.docker.container.image.v1+json

# Step 1: Get a bearer token
TOKEN=$(curl -s -u "$USERNAME:$PASSWORD" \
"https://auth.docker.io/token?service=registry.docker.io&scope=repository:$REPO:push,pull" \
| jq -r .token)

# Create a dummy config blob and compute its digest
echo '{"architecture":"amd64","os":"linux","config":{},"rootfs":{"type":"layers","diff_ids":[]}}' > $CONFIG
DIGEST="sha256:$(sha256sum $CONFIG | awk '{print $1}')"

# Step 2: Check if the blob exists
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -I \
  -H "Authorization: Bearer $TOKEN" \
  https://registry-1.docker.io/v2/$REPO/blobs/$DIGEST)

if [ "$STATUS" != "200" ]; then
  # Step 3: Upload blob using monolithic upload
  LOCATION=$(curl -sI -X POST \
    -H "Authorization: Bearer $TOKEN" \
    https://registry-1.docker.io/v2/$REPO/blobs/uploads/ \
    | grep -i Location | tr -d '\r' | awk '{print $2}')

  curl -s -X PUT "$LOCATION&digest=$DIGEST" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary @$CONFIG
fi

# Step 4: Upload the manifest that references the config blob
MANIFEST=$(cat <<EOF
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {
    "mediaType": "$MIME_TYPE",
    "size": $(stat -c%s $CONFIG),
    "digest": "$DIGEST"
  },
  "layers": []
}
EOF
)

curl -s -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/vnd.docker.distribution.manifest.v2+json" \
  -d "$MANIFEST" \
  https://registry-1.docker.io/v2/$REPO/manifests/$TAG

echo "Pushed image to $REPO:$TAG"
```

This example pushes a minimal image with no layers. To push a complete image, repeat steps 2-3 for each layer and include the layer digests in the `layers[]` field of the manifest.

## Deleting Images

Deleting an image involves removing its manifest by digest. You must first retrieve the manifest digest, then issue a `DELETE` request using that digest.

Only untagged manifests (or those not referenced by other tags or images) can be deleted. If a manifest is still referenced, the registry returns `403 Forbidden`.

> **Note**
>
> Manifest deletion operations may experience latency and could return a `500 Internal Server Error` during deletion. The system automatically retries the deletion in the background, so the manifest will eventually be removed. You do not need to manually retry the request.

This section outlines the basic steps to delete an image using the registry API.

1. [Get a bearer token for the repository](https://docs.docker.com/reference/api/registry/auth/).
2. [Get the manifest](https://docs.docker.com/reference/api/registry/latest/operations/GetImageManifest/) using the image's tag.
3. Retrieve the `Docker-Content-Digest` header from the manifest response. This digest uniquely identifies the manifest.
4. [Delete the manifest](https://docs.docker.com/reference/api/registry/latest/operations/DeleteImageManifest/) using a `DELETE` request and the digest.

The following bash script example deletes the `latest` tag from `yourusername/helloworld` on Docker Hub. Replace `yourusername` with your Docker Hub username and `dckr_pat` with your Docker Hub personal access token.

```bash
#!/bin/bash

USERNAME=yourusername
PASSWORD=dckr_pat
REPO=yourusername/helloworld
TAG=latest

# Step 1: Get a bearer token
TOKEN=$(curl -s -u "$USERNAME:$PASSWORD" \
  "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$REPO:pull,push,delete" \
  | jq -r .token)

# Step 2 and 3: Get the manifest and extract the digest from response headers
DIGEST=$(curl -sI -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  https://registry-1.docker.io/v2/$REPO/manifests/$TAG \
  | grep -i Docker-Content-Digest | tr -d '\r' | awk '{print $2}')

echo "Deleting manifest with digest: $DIGEST"

# Step 4: Delete the manifest by digest
curl -s -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  https://registry-1.docker.io/v2/$REPO/manifests/$DIGEST

echo "Deleted image: $REPO@$DIGEST"
```

This example deletes the manifest for the `latest` tag. To fully delete all references to an image, ensure no other tags or referrers point to the same manifest digest.

## Operations

- [POST /v2/{name}/blobs/uploads/](https://docs.docker.com/reference/api/registry/latest/operations/InitiateBlobUpload/): Initiate blob upload or attempt cross-repository blob mount

- [GET /v2/{name}/blobs/uploads/{uuid}](https://docs.docker.com/reference/api/registry/latest/operations/GetBlobUploadStatus/): Get blob upload status

- [PUT /v2/{name}/blobs/uploads/{uuid}](https://docs.docker.com/reference/api/registry/latest/operations/CompleteBlobUpload/): Complete blob upload

- [DELETE /v2/{name}/blobs/uploads/{uuid}](https://docs.docker.com/reference/api/registry/latest/operations/CancelBlobUpload/): Cancel blob upload

- [PATCH /v2/{name}/blobs/uploads/{uuid}](https://docs.docker.com/reference/api/registry/latest/operations/UploadBlobChunk/): Upload blob chunk

- [GET /v2/{name}/blobs/{digest}](https://docs.docker.com/reference/api/registry/latest/operations/GetBlob/): Retrieve blob

- [HEAD /v2/{name}/blobs/{digest}](https://docs.docker.com/reference/api/registry/latest/operations/CheckBlobExists/): Check existence of blob

- [GET /v2/{name}/manifests/{reference}](https://docs.docker.com/reference/api/registry/latest/operations/GetImageManifest/): Get image manifest

- [PUT /v2/{name}/manifests/{reference}](https://docs.docker.com/reference/api/registry/latest/operations/PutImageManifest/): Put image manifest

- [DELETE /v2/{name}/manifests/{reference}](https://docs.docker.com/reference/api/registry/latest/operations/DeleteImageManifest/): Delete image manifest

- [HEAD /v2/{name}/manifests/{reference}](https://docs.docker.com/reference/api/registry/latest/operations/HeadImageManifest/): Check if manifest exists

## Schemas
