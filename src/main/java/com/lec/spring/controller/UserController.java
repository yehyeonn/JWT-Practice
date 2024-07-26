package com.lec.spring.controller;

import com.lec.spring.domain.User;
import com.lec.spring.service.UserService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController // 이거 뭐였지
@RequestMapping("/user")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/join")
    public String join(@RequestBody User user) {
        user = userService.join(user);
        if (user == null) return "JOIN FAILED";
        return "JOIN OK : " + user;
    }

}
