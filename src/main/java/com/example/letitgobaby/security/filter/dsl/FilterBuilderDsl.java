package com.example.letitgobaby.security.filter.dsl;

import javax.servlet.Filter;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.example.letitgobaby.security.filter.A_LoginFilter;
import com.example.letitgobaby.security.filter.B_LoginFilter;
import com.example.letitgobaby.security.filter.JwtVerifyFilter;
import com.example.letitgobaby.security.handler.LoginFailureHandler;
import com.example.letitgobaby.security.handler.LoginSuccessHandler;


public class FilterBuilderDsl extends AbstractHttpConfigurer<FilterBuilderDsl, HttpSecurity> {

  @Override
  public void configure(HttpSecurity http) throws Exception {
    AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);

    http.addFilterBefore(a_LoginFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);
    http.addFilterBefore(b_LoginFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);
    http.addFilterAt(jwtFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);
    super.configure(http);
  }

  public Filter a_LoginFilter(AuthenticationManager authenticationManager) {
    String LOGIN_URL = "/a/login";
    RequestMatcher login_requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.POST.name());
    A_LoginFilter filter = new A_LoginFilter(login_requestMatcher, authenticationManager);
    filter.setAuthenticationSuccessHandler(new LoginSuccessHandler());
    filter.setAuthenticationFailureHandler(new LoginFailureHandler());
    return filter;
  }

  public Filter b_LoginFilter(AuthenticationManager authenticationManager) {
    String LOGIN_URL = "/b/login";
    RequestMatcher login_requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.GET.name());
    B_LoginFilter filter = new B_LoginFilter(login_requestMatcher, authenticationManager);
    filter.setAuthenticationSuccessHandler(new LoginSuccessHandler());
    filter.setAuthenticationFailureHandler(new LoginFailureHandler());
    return filter;
  }

  public Filter jwtFilter(AuthenticationManager authenticationManager) {
    JwtVerifyFilter filter = new JwtVerifyFilter();
    filter.setAuthenticationManager(authenticationManager);
    return filter;
  }

}
