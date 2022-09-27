package com.example.letitgobaby.app.user;

import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.letitgobaby.enums.ErrorCode;
import com.example.letitgobaby.exceptions.SignUpException;
import com.example.letitgobaby.model.User;
import com.example.letitgobaby.model.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserAuthService {

  private final PasswordEncoder encoder;
  private final UserRepository userRepository;

  @Transactional
  public User createUser(String userId, String passwd) {
    Optional<User> user = this.userRepository.findByUserId(userId);
    if (user.isPresent()) {
      throw new SignUpException(ErrorCode.USER_ALREADY_EXIST.getValue());
    }

    User entity = User.builder()
      .userId(userId)
      .userName("NAME_"+userId)
      .password(this.encoder.encode(passwd))
      .userRole("USER")
      .build();

    return this.userRepository.save(entity);
  }

  @Transactional
  public User createTestUser() {
    Optional<User> user = this.userRepository.findByUserId("123");
    if (user.isPresent()) {  
      return null; 
    }

    User entity = User.builder()
      .userId("123")
      .userName("123")
      .password(this.encoder.encode("123"))
      .userRole("USER")
      .build();
    return this.userRepository.save(entity);
  }

}
