package com.lec.spring.config;

import com.lec.spring.domain.User;
import com.lec.spring.service.UserService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class PrincipalDetailsService implements UserDetailsService {

    // DB 와 동작하기 위해 UserService
    private final UserService userService;

    public PrincipalDetailsService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("loadUserByUsername(" + username + ") 호출");

        // DB 조회
        User user = userService.findByUsername(username);

        if (user != null) {
            //UserDetails에 담아서 return하면 AutneticationManager가 검증 함
            return new PrincipalDetails(user);
        }

        // 해당 username 의 user 가 없다면?
        // UsernameNotFoundException 을 throw 해주어야 한다.
        throw new UsernameNotFoundException(username);
        // ※ 주의! 여기서 null 리턴하면 예외 발생

    }
}
