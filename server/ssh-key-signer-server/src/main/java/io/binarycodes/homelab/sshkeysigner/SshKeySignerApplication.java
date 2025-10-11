package io.binarycodes.homelab.sshkeysigner;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import com.vaadin.flow.component.page.AppShellConfigurator;
import com.vaadin.flow.theme.Theme;

@SpringBootApplication
@ConfigurationPropertiesScan
@Theme("app-theme")
public class SshKeySignerApplication implements AppShellConfigurator {

    public static void main(final String[] args) {
        SpringApplication.run(SshKeySignerApplication.class, args);
    }

}
