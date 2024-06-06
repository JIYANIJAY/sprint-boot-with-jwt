package com.spring.jwt.repository;

import com.spring.jwt.entity.UserAuth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserAuthRepository extends JpaRepository<UserAuth, Long> {
    boolean existsByAccessToken(String token);
}
