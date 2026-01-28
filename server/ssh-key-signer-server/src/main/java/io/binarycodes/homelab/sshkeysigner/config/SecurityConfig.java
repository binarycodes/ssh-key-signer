package io.binarycodes.homelab.sshkeysigner.config;

import com.vaadin.flow.spring.security.VaadinAwareSecurityContextHolderStrategyConfiguration;
import com.vaadin.flow.spring.security.VaadinSecurityConfigurer;
import com.vaadin.hilla.route.RouteUtil;
import org.jspecify.annotations.NonNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Import(VaadinAwareSecurityContextHolderStrategyConfiguration.class)
public class SecurityConfig {

    private final RouteUtil routeUtil;

    public SecurityConfig(final RouteUtil routeUtil) {
        this.routeUtil = routeUtil;
    }

    @Bean
    SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(registry -> {
                    registry.requestMatchers("/actuator/health/**").permitAll();
                    registry.requestMatchers(routeUtil::isRouteAllowed).authenticated();
                })
                .oauth2Login(Customizer.withDefaults())
                .oauth2ResourceServer(resourceServerConfigurer -> resourceServerConfigurer.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
                .csrf(config -> {
                    config.ignoringRequestMatchers("/rest/key/**");
                })
                .with(VaadinSecurityConfigurer.vaadin(), configurer -> {
                })
                .build();
    }

    @Bean
    public Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
        return new Converter<>() {
            private static final String PREFERRED_USERNAME_CLAIM_NAME = "preferred_username";
            private static final String CLIENT_ID_CLAIM_NAME = "client_id";
            private static final String SUBJECT_CLAIM_NAME = "sub";

            private final Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

            @Override
            public AbstractAuthenticationToken convert(@NonNull final Jwt jwt) {
                final var authorities = this.jwtGrantedAuthoritiesConverter.convert(jwt);
                final var principalClaimValue = extractPrincipalClaimValue(jwt);
                return new JwtAuthenticationToken(jwt, authorities, principalClaimValue);
            }

            private String extractPrincipalClaimValue(@NonNull final Jwt jwt) {
                final var clientId = jwt.getClaimAsString(CLIENT_ID_CLAIM_NAME);
                final var preferredUsername = jwt.getClaimAsString(PREFERRED_USERNAME_CLAIM_NAME);
                final var sub = jwt.getClaimAsString(SUBJECT_CLAIM_NAME);

                if (clientId != null && (preferredUsername == null || ("service-account-" + clientId).equals(preferredUsername))) {
                    return clientId; // client credentials -> use client_id
                }

                if (preferredUsername != null) {
                    // user flows -> use preferred_username when present, else fall back
                    return preferredUsername;
                }

                return sub;
            }
        };
    }

}
