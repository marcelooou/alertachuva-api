package com.fiap.alertachuva.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/auth/**",
                    "/swagger-ui/**",
                    "/v3/api-docs/**",
                    "/areas/**",
                    "/sensores/**",
                    "/leituras/**",
                    "/equipes/**",
                    "/alertas-incendio/**",
                    "/users/**"
                ).permitAll()
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
