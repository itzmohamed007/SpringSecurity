package com.security.security.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/security")
public class Controller {
    @GetMapping
    public ResponseEntity<Map<String, String>> hello() {
        return new ResponseEntity<>(Map.of("Message", "Hello"), HttpStatus.OK);
    }

    @GetMapping("user")
    @PreAuthorize("hasAuthority('USER')")
    public ResponseEntity<Map<String, Object>> permissionForUserAuthority() {
        return new ResponseEntity<>(Map.of("role", "USER"), HttpStatus.OK);
    }

    @GetMapping("admin")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Map<String, Object>> permissionForAdminAuthority() {
        return new ResponseEntity<>(Map.of("role", "ADMIN"), HttpStatus.OK);
    }

    @GetMapping("any")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'USER')")
    public ResponseEntity<Map<String, Object>> permissionForAllRoles() {
        return new ResponseEntity<>(Map.of("role", "ADMIN, USER"), HttpStatus.OK);
    }

    @GetMapping("auth")
    public ResponseEntity<Map<String, Object>> authenticatedUser(Authentication authentication) {
        return new ResponseEntity<>(Map.of("you", authentication.getPrincipal()), HttpStatus.OK);
    }
}
