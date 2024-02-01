package org.youcode.security.seeder;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.youcode.security.model.Role;
import org.youcode.security.repository.RoleRepository;

@Configuration
@RequiredArgsConstructor
public class RoleSeeder implements CommandLineRunner {
    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        if (roleRepository.findByAuthority("USER").isEmpty()) {
            Role userRole = new Role(0L, "USER");
            roleRepository.save(userRole);
        }

        if (roleRepository.findByAuthority("ADMIN").isEmpty()) {
            Role adminRole = new Role(0L, "ADMIN");
            roleRepository.save(adminRole);
        }
    }
}
