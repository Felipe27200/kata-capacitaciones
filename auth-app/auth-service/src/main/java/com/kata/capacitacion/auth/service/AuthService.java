package com.kata.capacitacion.auth.service;

import com.kata.capacitacion.auth.entity.User;
import com.kata.capacitacion.auth.repository.RoleRepository;
import com.kata.capacitacion.auth.repository.UserRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import dto.user.CreateUserDTO;
import dto.user.UserDTO;
import dto.login.LoginRequestDTO;
import dto.login.LoginResponseDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService
{
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtEncoder jwtEncoder;
    private final ModelMapper modelMapper;

    @Value("${app.jwt-expiration}")
    private Long jwtExpiration;

    public LoginResponseDTO login(LoginRequestDTO loginRequestDTO)
    {
        log.debug("[login] LoginRequestDTO: {}", loginRequestDTO.getUsername());

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    loginRequestDTO.getUsername(),
                    loginRequestDTO.getPassword()
                )
        );

        User user = userRepository.findByUsername(loginRequestDTO.getUsername())
                .orElseThrow(() -> {
                    log.error("[login] User not found: {}", loginRequestDTO.getUsername());

                    return new UsernameNotFoundException(loginRequestDTO.getUsername());
                });

        Instant currentTime = Instant.now();

        JwtClaimsSet claimsSet = JwtClaimsSet
                .builder()
                .subject(user.getUsername())
                .claim("role", user.getRole().getName())
                .claim("fullName", user.getFullName())
                .issuedAt(currentTime)
                .expiresAt(currentTime.plusSeconds(this.jwtExpiration))
                .build();

        var header = JwsHeader.with(MacAlgorithm.HS512).build();

        String token = jwtEncoder
                .encode(JwtEncoderParameters.from(header, claimsSet))
                .getTokenValue();

        return new LoginResponseDTO(
                token,
                "Bearer",
                this.modelMapper.map(user, UserDTO.class)
        );
    }

    public UserDTO register(CreateUserDTO createUserDTO)
    {
        log.debug("[register] create user: {}", createUserDTO.getUsername());

        var user = modelMapper.map(createUserDTO, User.class);

        var role = this.roleRepository.findById(createUserDTO.getRoleFk())
                .orElseThrow(() -> {
                    log.error("[register] Role not found: {}", createUserDTO.getRoleFk());

                    return new RuntimeException("Role with id '" + createUserDTO.getRoleFk() + "' not found");
                });

        user.setPassword(passwordEncoder.encode(createUserDTO.getPassword()));
        user.setRole(role);

        user = this.userRepository.save(user);

        return this.modelMapper.map(user, UserDTO.class);
    }
}
