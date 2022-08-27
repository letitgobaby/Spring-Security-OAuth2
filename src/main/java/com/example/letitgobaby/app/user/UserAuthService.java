package com.example.letitgobaby.app.user;

import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.letitgobaby.model.User;
import com.example.letitgobaby.model.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserAuthService {

  private final PasswordEncoder encoder;
  private final UserRepository userRepository;

  @Transactional
  public void createTestUser() {
    Optional<User> user = this.userRepository.findByUserId("123");
    if (!user.isPresent()) {
      User entity = User.builder()
      .userId("123")
      .userName("123")
      .password(this.encoder.encode("123"))
      .userRole("USER")
      .build();
  
      this.userRepository.save(entity);
    }
  }

}
