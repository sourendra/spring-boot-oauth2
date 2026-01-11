package com.example.springbootoauth2demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.*;
import java.util.stream.Collectors;

@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class SecurityConfig {

    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {
        this.clientRegistrationRepository = clientRegistrationRepository;
        OidcClientInitiatedLogoutSuccessHandler handler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        handler.setPostLogoutRedirectUri("{baseUrl}");
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/login", "/auth/login", "/auth/refresh-token")
                    .permitAll()
                    .anyRequest().authenticated())
            .oauth2Login(oauth2-> oauth2
//                    .loginPage("/login")
                    .defaultSuccessUrl("/home", true)
                    .userInfoEndpoint(userInfo -> userInfo
                            .userAuthoritiesMapper(userAuthoritiesMapper())))
            .logout(logout -> logout
                    .logoutSuccessHandler(handler)
                    .invalidateHttpSession(true)
                    .clearAuthentication(true)
            )
            .oauth2ResourceServer(oauth2-> oauth2
                    .jwt(jwt-> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter)));
//            .oauth2Login(Customizer.withDefaults());
        return http.build();
    }

    public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            Map<String, Object> clientAccess = (Map<String, Object>) jwt.getClaims().get("client-access");
            if (clientAccess == null || clientAccess.isEmpty()) return Collections.emptyList();

            return ((List<String>) clientAccess.get("roles")).stream()
                    .map(roleName -> "ROLE_" + roleName.toUpperCase()) // Spring requires "ROLE_" prefix
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation("http://localhost:9090/realms/test-realm1");
    }

    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority oidcAuth) {
                    // Extract roles from Keycloak's OIDC 'realm_access' claim
                    Map<String, Object> clientAccess = oidcAuth.getAttributes().get("client-access") instanceof Map
                            ? (Map<String, Object>) oidcAuth.getAttributes().get("client-access")
                            : Collections.emptyMap();

                    List<String> roles = (List<String>) clientAccess.get("roles");
                    if (roles != null) {
                        mappedAuthorities.addAll(roles.stream()
                                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                                .toList());
                    }
                }
            });
            return mappedAuthorities;
        };
    }
}
