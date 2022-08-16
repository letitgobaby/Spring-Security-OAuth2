package com.example.letitgobaby.security.provider;

import java.util.Arrays;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.example.letitgobaby.model.User;
import com.example.letitgobaby.model.UserRepository;
import com.example.letitgobaby.security.token.A_UserDetails;

public class UserDetailsServiceImpl implements UserDetailsService {
  
  private UserRepository userRepository;

  public UserDetailsServiceImpl(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    Optional<User> user = this.userRepository.findByUserId(username);
    if (!user.isPresent()) {
      throw new UsernameNotFoundException("User Not Found !!");
    }

    A_UserDetails userDetail = new A_UserDetails();
    userDetail.setUsername(user.get().getUserId());
    userDetail.setPassword(user.get().getPassword());

    GrantedAuthority author = new SimpleGrantedAuthority(user.get().getUserRole());
    userDetail.setAuthorities(Arrays.asList(author));

    return userDetail;
  }
}
