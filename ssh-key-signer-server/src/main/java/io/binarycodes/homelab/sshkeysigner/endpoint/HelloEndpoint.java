package io.binarycodes.homelab.sshkeysigner.endpoint;

import com.vaadin.hilla.BrowserCallable;
import jakarta.annotation.security.PermitAll;

@BrowserCallable
@PermitAll
public class HelloEndpoint {

    public String sayHello(String name) {
        if (name.isEmpty()) {
            return "Hello stranger";
        } else {
            return "Hello " + name;
        }
    }

}