package com.sqber.jwtTest.controller;

import com.sqber.jwtTest.security.CustomUserService;
import com.sqber.jwtTest.security.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Objects;

@RestController
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserService userService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @PostMapping("/auth")
    public ResponseEntity<?> auth(@RequestBody AuthRequest request){

        String username = request.getUsername();
        String password = request.getPassword();

        if(StringUtils.isEmpty(username) || StringUtils.isEmpty(password)){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("用户名或密码不能为空");
        }

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("用户不可用");
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("用户名或密码不正确");
        }

        UserDetails userDetails = userService.loadUserByUsername(username);
        String token = jwtTokenUtil.generateToken(userDetails);
        return ResponseEntity.ok(token);
    }

    @GetMapping("/auth/refresh")
    public ResponseEntity<?> refreshAndGetAuthenticationToken(HttpServletRequest request) {
         String authToken = request.getHeader("Authorization");
        final String token = authToken.substring(7);
        //String username = jwtTokenUtil.getUsernameFromToken(token);

        if (jwtTokenUtil.canTokenBeRefreshed(token)) {
            String refreshedToken = jwtTokenUtil.refreshToken(token);
            return ResponseEntity.ok(refreshedToken);
        } else {
            return ResponseEntity.badRequest().body(null);
        }
    }
}
