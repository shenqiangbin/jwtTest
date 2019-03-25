package com.sqber.jwtTest.security;

import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class JwtAuthorizationTokenFilter extends OncePerRequestFilter {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        boolean isAuth = request.getRequestURI().startsWith("/auth");

        String authorization = request.getHeader("Authorization");

        String username = null;
        String authToken = null;

        if(!isAuth && !StringUtils.isEmpty(authorization) && authorization.startsWith("Bearer ")){
            authToken = authorization.substring(7);
            try {
                username = jwtTokenUtil.getUsernameFromToken(authToken);
            } catch (IllegalArgumentException e) {
                logger.error("an error occurred during getting username from token", e);
            } catch (ExpiredJwtException e) {
                response.setStatus(402);
                response.getWriter().write("{code:402,msg:'token expired'}");
                //response.sendError(HttpServletResponse.SC_GONE, "超时");
                //response.getWriter().write("token expired");
                //logger.warn("the token is expired and not valid anymore", e);
                return;
            }
        }else {
            logger.warn("couldn't find bearer string, will ignore the header");
        }

        if(username!=null && SecurityContextHolder.getContext().getAuthentication() == null){

            JwtUser userdb =  getUser(username);
            if(userdb!=null) {
                List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
                GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("admin");
                grantedAuthorities.add(grantedAuthority);

                String encodePassword = new BCryptPasswordEncoder().encode(userdb.getPassword());

                JwtUser user = new JwtUser(username,encodePassword,grantedAuthorities);

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
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
