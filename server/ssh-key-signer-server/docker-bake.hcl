variable "REGISTRY" { default = "docker.io/binarycodes" }
variable "APP_NAME" { default = "ssh-key-signer-server" }
variable "APP_VERSION" { default = "0.0.10" }

variable "TAG_NAME" { default = "ssh-key-signer" }

group "default" {
  targets = ["app"]
}

target "app" {
  context    = "."
  dockerfile = "Dockerfile"

  args = {
    APP_NAME    = "${APP_NAME}"
    APP_VERSION = "${APP_VERSION}"
  }

  tags = [
    "${REGISTRY}/${TAG_NAME}:${APP_VERSION}",
    "${REGISTRY}/${TAG_NAME}:latest",
  ]

  platforms = ["linux/amd64"]
}
