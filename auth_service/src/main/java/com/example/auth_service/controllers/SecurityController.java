package com.example.auth_service.controllers;

import com.example.auth_service.model.SigninRequest;
import com.example.auth_service.model.SignupRequest;
import com.example.auth_service.model.User;
import com.example.auth_service.model.UserInfo;
import com.example.auth_service.repository.UserRepository;
import com.example.auth_service.service.JwtCore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/auth")
public class SecurityController {

    private UserRepository userRepository;
    private AuthenticationManager authenticationManager;
    private PasswordEncoder passwordEncoder;
    private JwtCore jwtCore;

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    @Autowired
    public void setJwtCore(JwtCore jwtCore) {
        this.jwtCore = jwtCore;
    }
    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Autowired
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/signup")
    ResponseEntity<?> signup(@RequestBody SignupRequest signupRequest) {
        if(userRepository.existsByName(signupRequest.getName())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Choose different name");
        }
        if(userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Choose different email");
        }

        User user = new User();
        user.setName(signupRequest.getName());
        user.setEmail(signupRequest.getEmail());
        user.setPassword_hash(passwordEncoder.encode(signupRequest.getPassword()));
        userRepository.save(user);
        return ResponseEntity.ok("Success");
    }

    @PostMapping("/signin")
    ResponseEntity<?> signin(@RequestBody SigninRequest signinRequest) {
        Authentication authentication = null;
        try{
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signinRequest.getName(), signinRequest.getPassword()));
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtCore.generateToken(authentication);
        return ResponseEntity.ok(jwt);
    }

}