package com.sqber.jwtTest.security;

import io.jsonwebtoken.Jwt;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CustomUserService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //通过username在库中查找user信息

        JwtUser userdb = getUser(username);

        if (userdb == null)
            throw new UsernameNotFoundException(String.format("用户未找到 '%s'.", username));

        String password = userdb.getPassword();


        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("admin");
        grantedAuthorities.add(grantedAuthority);

        String encodePassword = new BCryptPasswordEncoder().encode(password);

        JwtUser user = new JwtUser(username, encodePassword, grantedAuthorities);
        return user;

    }

    private JwtUser getUser(String username) {
        List<JwtUser> list = new ArrayList<>();

        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("admin");
        grantedAuthorities.add(grantedAuthority);

        list.add(new JwtUser("user1", "user1", grantedAuthorities));
        list.add(new JwtUser("user2", "user2", grantedAuthorities));

        for (JwtUser user : list) {
            if (user.getUsername().equals(username))
                return user;
        }

        return null;
    }
}
