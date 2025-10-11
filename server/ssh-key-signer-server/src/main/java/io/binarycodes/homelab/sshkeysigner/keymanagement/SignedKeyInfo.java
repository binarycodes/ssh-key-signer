package io.binarycodes.homelab.sshkeysigner.keymanagement;

public record SignedKeyInfo(KeyInfo keyInfo, String signedKey) {
}
