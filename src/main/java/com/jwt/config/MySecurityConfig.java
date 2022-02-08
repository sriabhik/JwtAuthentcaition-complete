package com.jwt.config;

import com.fasterxml.jackson.databind.annotation.NoClass;
import com.jwt.services.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
//extends WebSecurityCon.. class to overide it's method and make changes a per requirment
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomUserDetailService customUserDetailService;

    //this authwired for filter
    @Autowired
    private JwtAuthenticationFilter jwtFilter;
    //this two method get override

    //1
    //this method define,which url to permit,means only authencticatin user can user,disable crss
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailService);
    }



    //2
    //which authentication do we have to user,jdbcauthentication,or userDetailsAuthentication(cutom class)
    //which class authentication we want,we should make it autowired here as above
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //1)csrf ;; Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users
                // to submit a request to a Web application against which they are currently authenticated.

        //2)Cross-Origin Resource Sharing (CORS) is an HTTP-header based mechanism that allows a server to indicate any origins
          // (domain, scheme, or port) other than its own from which a browser should permit loading resources
        //3)antmatcher allow permit to a specfic url
        http
                .csrf()
                .disable()

                .cors()
                .disable()

                .authorizeRequests()
                .antMatchers("/token").permitAll()

                .anyRequest().authenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        //this step after JwtAuthentication filter class
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }

    //here we user nean of password encoder
    //for athentication mamager we need a bean
    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception{
        return super.authenticationManagerBean();
    }
}
