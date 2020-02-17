package com.javainuse.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class JwtUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        if ("javainuse".equals(userName)) {
            return new User("javainuse", "$2a$10$3DOrUAUAlAjW5JD2msD6O.707JSuhAFsMzC.355VNxWLa/51YsTHy",
                    new ArrayList<>());
        } else {
            throw new UsernameNotFoundException("User not found with username: " + userName);
        }
    }
}
