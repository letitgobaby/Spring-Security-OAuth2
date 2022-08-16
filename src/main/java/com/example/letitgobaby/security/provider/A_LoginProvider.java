package com.example.letitgobaby.security.provider;

import java.util.Arrays;
import java.util.Optional;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.example.letitgobaby.model.User;
import com.example.letitgobaby.model.UserRepository;
import com.example.letitgobaby.security.token.A_UserDetails;
import com.example.letitgobaby.security.token.AuthUserToken;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class A_LoginProvider implements AuthenticationProvider {

  private final UserRepository userRepository;

  // public A_LoginProvider(UserRepository userRepository) {
  //   this.userRepository = userRepository;
  // }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return AuthUserToken.class.isAssignableFrom(authentication);
  }
  
}
