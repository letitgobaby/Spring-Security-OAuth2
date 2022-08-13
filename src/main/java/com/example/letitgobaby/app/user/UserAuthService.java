package com.example.letitgobaby.app.user;

import org.springframework.stereotype.Service;

import com.example.letitgobaby.model.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserAuthService {
  
  private final UserRepository userRepository;

}
