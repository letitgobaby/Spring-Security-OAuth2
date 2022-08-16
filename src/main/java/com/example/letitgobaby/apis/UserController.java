package com.example.letitgobaby.apis;

import java.security.Principal;
import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import lombok.RequiredArgsConstructor;

@Controller
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
  
  @GetMapping("/test")
  public void test(Principal principal) {
    System.out.println("\n\n");
    System.out.println(principal);
    System.out.println("\n\n");
  }

  @PostMapping("/login")
  public void login(Map<String, String> body) {
    System.out.println("\n\n");
    System.out.println("hello");
    System.out.println("\n\n");
  }
}
