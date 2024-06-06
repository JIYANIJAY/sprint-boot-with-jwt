package com.spring.jwt.config.jwt;

import com.spring.jwt.entity.Users;
import com.spring.jwt.repository.UserAuthRepository;
import com.spring.jwt.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

@Service
public class JwtTokenService {

    private String jwtSecret="nitialized JPA EntityManagerFactory for persistence unit 'default'";

    private String tokenValidity="100000";

    private String refreshTokenValidity="100000";

    private final UserRepository userRepository;
    private final UserAuthRepository userAuthRepository;

    public JwtTokenService(UserRepository userRepository, UserAuthRepository userAuthRepository) {
        this.userRepository = userRepository;
        this.userAuthRepository = userAuthRepository;
    }

    public long getTokenValidity() {
        return Long.parseLong(tokenValidity);
    }

    public long getRefreshTokenValidity() {
        return Long.parseLong(refreshTokenValidity);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInkey())
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    private Key getSignInkey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(HashMap<String, Object> extraClaims, Users user) {
        extraClaims.put("role", "admin");
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(user.getEmail())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + getTokenValidity()))
                .signWith(getSignInkey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken(Users user) {
        return generateToken(new HashMap<>(), user);
    }

    public String generateRefreshToken(HashMap<String, Object> extraClaims, Users user) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(user.getEmail())
                .setIssuedAt(new Date(System.currentTimeMillis()))
//				.setExpiration(new Date(System.currentTimeMillis() + getRefreshTokenValidity()))
                .signWith(getSignInkey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(Users user) {
        return generateRefreshToken(new HashMap<>(), user);
    }

    public boolean isTokenValid(String token) {
        if (isTokenExpired(token)) {
            return false;
        }
        return userAuthRepository.existsByAccessToken(token);
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Date extractIssuedAt(String token) {
        return extractClaim(token, Claims::getIssuedAt);
    }

    public boolean validateRefreshToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(getSignInkey()).build().parseClaimsJws(token);
            return true;
        } catch (MalformedJwtException e) {
        } catch (ExpiredJwtException e) {
        } catch (UnsupportedJwtException e) {
        } catch (IllegalArgumentException e) {
        }
        return false;
    }
}
