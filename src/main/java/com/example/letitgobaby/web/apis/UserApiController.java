package com.example.letitgobaby.web.apis;

import java.security.Principal;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.example.letitgobaby.app.user.UserAuthService;
import com.example.letitgobaby.model.User;
import com.example.letitgobaby.model.UserRepository;
import com.example.letitgobaby.web.apis.payload.SignUpPayload;
import com.example.letitgobaby.web.apis.results.ApiResult;

import lombok.RequiredArgsConstructor;

@Controller
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserApiController {
  
  private final PasswordEncoder encoder;

  private final UserAuthService userAuthService;

  @GetMapping("/info")
  public ResponseEntity<ApiResult> getAuthenticatedUserInfo(Authentication auth) {
    ApiResult result = new ApiResult(HttpStatus.OK.value(), "Authenticated User Info").body(auth.getPrincipal());

    return ResponseEntity.ok(result);
  }

  @PostMapping("/signUp")
  public ResponseEntity<ApiResult> signUp(@RequestBody SignUpPayload payload) {
    User newUser = this.userAuthService.createUser(payload.getUserId(), payload.getPassword());
    ApiResult result = new ApiResult(HttpStatus.CREATED.value(), "CREATE")
      .body(newUser);
    return ResponseEntity.ok(result);
  }

  @GetMapping("/test")
  public ResponseEntity<ApiResult> createUser(String pw) {
    System.out.println("\n\n");
    System.out.println(pw + " / " + this.encoder.encode(pw));
    System.out.println("\n\n");
    this.userAuthService.createTestUser();
    return ResponseEntity.ok().build();
  }

  @GetMapping("/auth/test")
  public void authTest(Principal principal) {
    System.out.println("\n\n");
    System.out.println(principal);
    System.out.println("\n\n");
  }

  

}
