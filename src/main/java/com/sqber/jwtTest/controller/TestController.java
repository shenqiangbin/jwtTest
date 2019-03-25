package com.sqber.jwtTest.controller;

import com.sqber.jwtTest.security.JwtUser;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/test/hello")
    public String hello(){
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        JwtUser user = (JwtUser)auth.getPrincipal();
        return "hello" + user.getUsername();
    }

    @GetMapping("/test/test2")
    public Object test2(){
        return ResponseEntity.ok("ok");
    }
}
