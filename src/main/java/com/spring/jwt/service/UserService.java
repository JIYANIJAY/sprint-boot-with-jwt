package com.spring.jwt.service;

import com.spring.jwt.dto.TokenDTO;
import com.spring.jwt.entity.Users;

public interface UserService {
    TokenDTO getToken(String userName, String password);

    Users saveUser(Users users);
}
