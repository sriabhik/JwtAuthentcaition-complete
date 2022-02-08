package com.jwt.controller;

import com.jwt.helper.JwtUtils;
import com.jwt.model.JwtRequest;
import com.jwt.model.JwtResponse;
import com.jwt.services.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtController {

    //these three authowied use to generate token

    @Autowired
    private CustomUserDetailService customUserDetailService;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private AuthenticationManager authenticationManager;
    @RequestMapping(value = "token",method = RequestMethod.POST)
    public ResponseEntity<?> generateToken(@RequestBody JwtRequest jwtRequest) throws Exception {
        System.out.println(jwtRequest);
        try{
            //this used for authentication
            this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(jwtRequest.getUsername(),jwtRequest.getPassword()));
        }catch (UsernameNotFoundException e){
            e.printStackTrace();
            throw new Exception(
                    "bad creadentials"
            );
        }catch (Exception e){
            e.printStackTrace();
        }

        UserDetails userDetails = this.customUserDetailService.loadUserByUsername(jwtRequest.getUsername());
        //jwtutils have this method which generate one token for one user
        String token = this.jwtUtils.generateToken(userDetails);
        System.out.println("JWT token  : "+token);
        //returnin token and user details
        //we create jwt response class
        return ResponseEntity.ok(new JwtResponse(token));
    }
}
