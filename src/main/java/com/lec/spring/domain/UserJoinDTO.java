package com.lec.spring.domain;

import lombok.Data;
import lombok.NoArgsConstructor;

// 회원 가입시 parameter 받아오는 DTO(Data Transfer Object)
@Data
@NoArgsConstructor
public class UserJoinDTO {
    private String username;
    private String password;
}
