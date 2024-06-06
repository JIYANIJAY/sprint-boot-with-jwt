package com.spring.jwt.service.impl;

import com.spring.jwt.config.jwt.JwtTokenService;
import com.spring.jwt.dto.TokenDTO;
import com.spring.jwt.entity.UserAuth;
import com.spring.jwt.entity.Users;
import com.spring.jwt.repository.UserAuthRepository;
import com.spring.jwt.repository.UserRepository;
import com.spring.jwt.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;
    private final UserAuthRepository userAuthRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, AuthenticationManager authenticationManager, JwtTokenService jwtTokenService, UserAuthRepository userAuthRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.jwtTokenService = jwtTokenService;
        this.userAuthRepository = userAuthRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public TokenDTO getToken(String email, String password) {
        Users users = userRepository.findByEmail(email);
        if (users == null) {
            return null;
        }

        authenticateUser(email, password);

        return tokenData(users);
    }

    @Override
    public Users saveUser(Users user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    protected TokenDTO tokenData(Users user) {
        //Generate new Token and get all data
        String jwtToken = jwtTokenService.generateToken(user);
        String refreshToken = jwtTokenService.generateRefreshToken(user);
        Date expiresAt = jwtTokenService.extractExpiration(jwtToken);
        Date issuedAt = jwtTokenService.extractIssuedAt(jwtToken);

        //Save Token data in database
        UserAuth userAuth = new UserAuth();
        userAuth.setAccessToken(jwtToken);
        userAuth.setRefreshToken(refreshToken);
        userAuth.setExpiresAt(expiresAt);
        userAuth.setIssuedAt(issuedAt);
        userAuthRepository.save(userAuth);

        return new TokenDTO(jwtToken, refreshToken);
    }

    protected void authenticateUser(String email, String password) {
        try {
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(email, password));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (BadCredentialsException e) {
            log.error(e.getLocalizedMessage());
        }
    }
}
