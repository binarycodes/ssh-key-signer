package io.binarycodes.homelab.sshkeysigner.usermanagement;

import java.util.List;

public record UserProfile(String name,
                          String email,
                          List<String> authorities) {
}
