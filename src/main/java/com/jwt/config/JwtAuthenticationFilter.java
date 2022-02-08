package com.jwt.config;

import com.jwt.helper.JwtUtils;
import com.jwt.services.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//Filter base class that aims to guarantee a single execution per request dispatch, on any servlet container.
// It provides a doFilterInternal(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse,
// javax.servlet.FilterChain) method with HttpServletRequest and HttpServletResponse arguments.
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    //using JwtUtils to get username
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private CustomUserDetailService customUserDetailService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //get jwt
        //Bearer
        //validate
        //this request we are getting rom http
        String requestTokenHeader = request.getHeader("Authorization");
        String username = null;
        String jwtToken = null;

        //valiating token
        if(requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")){
            jwtToken = requestTokenHeader.substring(7);
            try{
                //geeting user name
                username = this.jwtUtils.extractUsername(jwtToken);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        else{
            System.out.println("Invalid Token,not start wth bearer");
        }

        //load userdetails
        UserDetails  userDetails = this.customUserDetailService.loadUserByUsername(username);
        //security

        //The SecurityContext is used to store the details of the currently authenticated user, also known as a principle.
        // So, if you have to get the username or any other user details, you need to get this SecurityContext first.
        // The SecurityContextHolder is a helper class, which provides access to the security context.//basically
        ///bsaicallyy its a null check
        if(username != null && SecurityContextHolder.getContext().getAuthentication()==null){
            UsernamePasswordAuthenticationToken usernamePasswordAuthentication = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
            usernamePasswordAuthentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthentication);
        }
        else {
            System.out.println("Token is not valid");
        }

        filterChain.doFilter(request,response);
    }

}
