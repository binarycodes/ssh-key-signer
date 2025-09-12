package io.binarycodes.homelab.sshkeysigner.config;


import com.vaadin.flow.spring.security.VaadinWebSecurity;
import com.vaadin.hilla.route.RouteUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig extends VaadinWebSecurity {

    private final RouteUtil routeUtil;

    public SecurityConfig(RouteUtil routeUtil) {
        this.routeUtil = routeUtil;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(registry -> {
            registry.requestMatchers(routeUtil::isRouteAllowed)
                    .authenticated();
        });
        http.oauth2ResourceServer(resourceServerConfigurer -> resourceServerConfigurer.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));
        super.configure(http);

        http.csrf(config -> {
            config.ignoringRequestMatchers("/rest/key/**");
        });

        http.oauth2Login(Customizer.withDefaults());
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        final var converter = new JwtAuthenticationConverter();
        converter.setPrincipalClaimName("preferred_username");
        return converter;
    }

}
