package com.example.springbootoauth2demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {
        this.clientRegistrationRepository = clientRegistrationRepository;
        OidcClientInitiatedLogoutSuccessHandler handler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        handler.setPostLogoutRedirectUri("{baseUrl}");
        http
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/login")
                    .permitAll()
                    .anyRequest().authenticated())
            .oauth2Login(oauth2-> oauth2
//                    .loginPage("/login")
                    .defaultSuccessUrl("/home", true))
                .logout(logout -> logout
                        .logoutSuccessHandler(handler)
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                );
//            .oauth2Login(Customizer.withDefaults());
        return http.build();
    }
}
