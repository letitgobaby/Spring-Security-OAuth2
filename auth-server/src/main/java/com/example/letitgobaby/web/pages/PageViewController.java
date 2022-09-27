package com.example.letitgobaby.web.pages;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class PageViewController {
  
  @GetMapping("/login")
  public String loginPage() {
    return "login.html";
  }

  @GetMapping("/main")
  public String mainPage() {
    return "main.html";
  }

}
