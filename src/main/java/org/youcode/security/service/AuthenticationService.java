package org.youcode.security.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.youcode.security.model.Role;
import org.youcode.security.model.User;
import org.youcode.security.repository.RoleRepository;
import org.youcode.security.repository.UserRepository;

import java.util.ArrayList;
import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthenticationService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    public User register(String username, String password) {
        userRepository.findByUsername(username).ifPresent(user -> {
            throw new RuntimeException("Error: Username is already taken.");
        });

        String encodedPassword = passwordEncoder.encode(password);
        Role userRole = roleRepository.findByAuthority("USER")
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));

        List<Role> authorities = new ArrayList<>();
        authorities.add(userRole);

        return userRepository.save(new User(0L, username, encodedPassword, authorities));
    }

    public String login(String username, String password) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            return tokenService.generateJwt(auth);

        } catch (AuthenticationException e) {
            return "something went wrong when trying to authenticate";
        }
    }
}
