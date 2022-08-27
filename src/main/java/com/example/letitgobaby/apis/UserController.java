package com.example.letitgobaby.apis;

import java.security.Principal;
import java.util.Map;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.example.letitgobaby.app.user.UserAuthService;
import com.example.letitgobaby.model.User;
import com.example.letitgobaby.model.UserRepository;

import lombok.RequiredArgsConstructor;

@Controller
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
  
  private final PasswordEncoder encoder;

  private final UserAuthService userAuthService;

  @GetMapping("/test")
  public void createUser(String pw) {
    System.out.println("\n\n");
    System.out.println(pw + " / " + this.encoder.encode(pw));
    System.out.println("\n\n");
    this.userAuthService.createTestUser();
  }

  @GetMapping("/auth/test")
  public void authTest(Principal principal) {
    System.out.println("\n\n");
    System.out.println(principal);
    System.out.println("\n\n");
  }

  

}
