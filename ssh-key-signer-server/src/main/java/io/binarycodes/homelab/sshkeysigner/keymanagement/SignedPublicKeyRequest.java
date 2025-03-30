package io.binarycodes.homelab.sshkeysigner.keymanagement;

public record SignedPublicKeyRequest(String filename, String publicKey, String data) {
}
