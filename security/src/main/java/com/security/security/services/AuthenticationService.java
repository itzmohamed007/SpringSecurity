package com.security.security.services;

import com.security.security.jwt.JwtService;
import com.security.security.models.User;
import com.security.security.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationProvider authenticationProvider;

    public User register(User user) {
        User userToCreate = User.builder()
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .password(passwordEncoder.encode(user.getPassword()))
                .authority(user.getAuthority())
                .build();

        return userRepository.save(userToCreate);
    }

    public String login(String email, String password) {
        var user = authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        var userDetails = (User) user.getPrincipal();
        return jwtService.generateToken(userDetails, Map.of("fullname", userDetails.getFirstName() + " " + userDetails.getLastName()));
    }


}
