package com.spring.jwt.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity(name="USER_TOKENS")
public class UserAuth {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long userAuthId;

    private String accessToken;

    private String refreshToken;

    private String tokenType;

    private Date expiresAt;

    private Date issuedAt;

    private Date createdDate;

    private Date updatedDate;

}