package com.kata.capacitacion.auth.config;

import com.kata.capacitacion.auth.entity.Role;
import com.kata.capacitacion.auth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataLoader implements CommandLineRunner
{
    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        if (roleRepository.findByName("STUDENT").isEmpty()) {
            Role role = new Role();
            role.setName("STUDENT");

            roleRepository.save(role);
        }

        if (roleRepository.findByName("ADMIN").isEmpty()) {
            Role role = new Role();
            role.setName("ADMIN");

            roleRepository.save(role);
        }
    }
}
