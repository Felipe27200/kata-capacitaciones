package com.kata.capacitacion.auth.security;

import com.kata.capacitacion.auth.repository.UserRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Configuration
public class SecurityUtils {
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
    {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public JwtEncoder jwtEncoder(@Value("${app.jwt-secret}") String secretKey)
    {
        byte[] keyBytes = Base64.getDecoder().decode(secretKey);

        if (keyBytes.length != 64) {
            System.err.println("ERROR: La clave decodificada para HS512 debe ser de 64 bytes.");
            // Esto forzará una excepción temprana si el error es la longitud
            throw new IllegalArgumentException("Clave JWT de longitud incorrecta.");
        }

        SecretKey key = new SecretKeySpec(keyBytes, "HmacSHA512");

        // 2. Construir el JWK usando el objeto SecretKey (más robusto)
        JWK jwk = new OctetSequenceKey.Builder(key)
                .keyID("key-authentication")
                .algorithm(JWSAlgorithm.HS512)
                .keyUse(KeyUse.SIGNATURE)
                .build();

        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));

        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(@Value("${app.jwt-secret}") String secretKey)
    {
        byte[] decodedKey = Base64.getDecoder().decode(secretKey);

        SecretKey key = new SecretKeySpec(decodedKey, JWSAlgorithm.HS512.getName());
        return NimbusJwtDecoder.withSecretKey(key).build();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository)
    {
        // Get users from the database for logging
        return username -> userRepository.findByUsername(username)
                .map(user -> User.withUsername(user.getUsername())
                        .password(user.getPassword())
                        .roles(user.getRole().getName())
                        .build()
                )
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
    }
}
