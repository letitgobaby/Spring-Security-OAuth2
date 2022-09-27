package com.example.letitgobaby.web.pages;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/sub")
public class SubPageViewController {
  
  @GetMapping("/loginpage")
  public ModelAndView subLoginPage(ModelAndView mv) {
    mv.setViewName("/subLogin.html");
    return mv;
  }

  @GetMapping("/consent")
  public ModelAndView consentPage(ModelAndView mv) {
    mv.setViewName("/consent.html");

    return mv;
  }

}
