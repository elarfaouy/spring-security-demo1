package org.youcode.security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.youcode.security.model.User;
import org.youcode.security.service.AuthenticationService;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public User registerUser(@RequestBody User user){
        return authenticationService.register(user.getUsername(), user.getPassword());
    }

    @PostMapping("/login")
    public String loginUser(@RequestBody User user){
        return authenticationService.login(user.getUsername(), user.getPassword());
    }
}
