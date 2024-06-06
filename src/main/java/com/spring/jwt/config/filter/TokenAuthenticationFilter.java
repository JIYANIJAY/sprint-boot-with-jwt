package com.spring.jwt.config.filter;

import com.spring.jwt.config.UserDetailsServiceImpl;
import com.spring.jwt.config.jwt.JwtTokenService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;

    private final UserDetailsServiceImpl userDetailsServiceImpl;

    public TokenAuthenticationFilter(JwtTokenService jwtTokenService, UserDetailsServiceImpl userDetailsServiceImpl) {
        this.jwtTokenService = jwtTokenService;
        this.userDetailsServiceImpl = userDetailsServiceImpl;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String token;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);

            try {
                String username;
                boolean tokenValid;

                username = jwtTokenService.extractUsername(token);
                tokenValid = jwtTokenService.isTokenValid(token);

                UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(username);

                if (tokenValid) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                } else {
                    log.error("Token is not valid");
                }
            } catch (MalformedJwtException e) {
                throw new RuntimeException(e.getMessage());
            } catch (ExpiredJwtException e) {
                throw new RuntimeException(e.getMessage());
            } catch (UnsupportedJwtException e) {
                throw new RuntimeException(e.getMessage());
            } catch (IllegalArgumentException e) {
                throw new RuntimeException(e.getMessage());
            } catch (Exception e) {
                log.info("exception while authentication : ", e);
            }
        }
        filterChain.doFilter(request, response);
    }
}
