package io.binarycodes.homelab.sshkeysigner.usermanagement;

import java.util.List;
import java.util.stream.Collectors;

import jakarta.annotation.security.PermitAll;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import com.vaadin.hilla.BrowserCallable;

@BrowserCallable
public class UserProfileService {

    @PermitAll
    @NonNull
    public UserProfile getUserProfile() {
        final Authentication auth = SecurityContextHolder.getContext()
                .getAuthentication();

        final List<String> authorities = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return new UserProfile(auth.getName(), null, authorities);
    }
}
