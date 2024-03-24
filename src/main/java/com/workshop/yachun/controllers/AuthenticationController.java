package com.workshop.yachun.controllers;

import com.workshop.yachun.config.JwtUtils;
import com.workshop.yachun.dao.UserDao;
import com.workshop.yachun.dto.AuthenticationRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api/v1/auth")
//@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationManager authenticationManager;

    private final UserDao userDao;
    private final JwtUtils jwtUtils;

    @Autowired
    public AuthenticationController(AuthenticationConfiguration configuration, UserDao userDao, JwtUtils jwtUtils) throws Exception {
        this.authenticationManager = configuration.getAuthenticationManager();
        this.userDao = userDao;
        this.jwtUtils = jwtUtils;
    }

//    @PostMapping("/register")
//    public ResponseEntity<AuthenticationResponse> register(
//            @RequestBody RegisterRequest request
//    ) {
////        return ResponseEntity.ok(service.register(request));
//        authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
//        );
//        final UserDetails user = userDao.findUserByEmail(request.getEmail());
//        if (user != null) {
//            return ResponseEntity.ok(jwtUtils.generateToken(user));
//        }
//        return ResponseEntity.status(400).body("some error has occurred");
//    }

    @PostMapping("/authenticate")
    public ResponseEntity<String> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
//        return ResponseEntity.ok(service.authenticate(request));
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        final UserDetails user = userDao.findUserByEmail(request.getEmail());
        if (user != null) {
            return ResponseEntity.ok(jwtUtils.generateToken(user));
        }
        return ResponseEntity.status(400).body("some error has occurred");
    }
}
