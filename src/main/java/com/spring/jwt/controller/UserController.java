package com.spring.jwt.controller;


import com.spring.jwt.dto.TokenDTO;
import com.spring.jwt.dto.UserLogin;
import com.spring.jwt.entity.Users;
import com.spring.jwt.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/save/me")
    public ResponseEntity<Users> saveUser(@RequestBody Users users) {
        Users user = userService.saveUser(users);
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }

    @PostMapping("/auth/login")
    public ResponseEntity<TokenDTO> getUserToken(@RequestBody UserLogin userLogin) {
        return ResponseEntity.ok(userService.getToken(userLogin.getEmail(), userLogin.getPassword()));
    }

    @GetMapping("/hello")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello World");
    }
}
