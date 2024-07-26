package com.lec.spring.repository;

import com.lec.spring.domain.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class UserRepositoryTest {


    @Autowired
    UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;


    @Test
    void registerTest(){
        User user1 = User.builder()
                .username("user1".toUpperCase())
                .password(passwordEncoder.encode("1234"))
                .role("ROLE_MEMBER")
                .build();


        User user2 = User.builder()
                .username("user2".toUpperCase())
                .password(passwordEncoder.encode("1234"))
                .build();


        User admin1 = User.builder()
                .username("admin1".toUpperCase())
                .password(passwordEncoder.encode("1234"))
                .role("ROLE_MEMBER,ROLE_ADMIN")
                .build();


        userRepository.saveAllAndFlush(List.of(user1, user2, admin1));
    }



}