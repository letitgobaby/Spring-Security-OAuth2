package com.example.letitgobaby.web.apis;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.example.letitgobaby.web.apis.results.ApiResult;

import lombok.RequiredArgsConstructor;

@Controller
@RequestMapping("/sub")
@RequiredArgsConstructor
public class SubApiController {

  @GetMapping("/a")
  public ResponseEntity<ApiResult> testA() {
    return ResponseEntity.ok().build();
  }
  
  @PostMapping("/b")
  public ResponseEntity<ApiResult> testB() {
    return ResponseEntity.ok().build();
  }

  @PatchMapping("/c")
  public ResponseEntity<ApiResult> testC() {
    return ResponseEntity.ok().build();
  }

}
