package io.binarycodes.homelab.sshkeysigner.endpoint;

import jakarta.annotation.security.PermitAll;

import com.vaadin.hilla.BrowserCallable;

@BrowserCallable
@PermitAll
public class HelloEndpoint {

    public String sayHello(final String name) {
        if (name.isEmpty()) {
            return "Hello stranger";
        } else {
            return "Hello " + name;
        }
    }

}