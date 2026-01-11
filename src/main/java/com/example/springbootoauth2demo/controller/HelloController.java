package com.example.springbootoauth2demo.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class HelloController {

    private static final Logger log = LoggerFactory.getLogger(HelloController.class);

    @GetMapping("/home")
    public String greet(@AuthenticationPrincipal OidcUser user){
        log.warn("claims: {}", user.getClaims());
        Map<String, Object> realmAccess =
                (Map<String, Object>) user.getClaims().get("client-access");
        List<String> roles = (List<String>) realmAccess.get("roles");
        log.warn("roles: {}", roles);
//        log.warn("roles: {}", user.getAuthorities());
        return "Welcome to Spring Boot OAuth2!" + user.toString();
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public String userEndpoint() {
        return "Hello User!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminEndpoint() {
        return "Hello Admin!";
    }
}
