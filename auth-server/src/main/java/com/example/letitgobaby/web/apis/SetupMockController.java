package com.example.letitgobaby.web.apis;

import javax.xml.ws.Response;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.example.letitgobaby.app.clients.ClientInfoService;
import com.example.letitgobaby.app.user.UserAuthService;
import com.example.letitgobaby.model.ClientInfo;
import com.example.letitgobaby.model.User;
import com.example.letitgobaby.web.apis.results.ApiResult;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequestMapping("/test")
@RequiredArgsConstructor
public class SetupMockController {
  
  private final UserAuthService userAuthService;
  private final ClientInfoService clientInfoService;

  @GetMapping("/setup")
  public ResponseEntity<ApiResult> setUpForTest() {
    log.info("## SET-UP TEST DATAS ##");

    String mockId = "abc";
    String mockSecret = "abc";

    ClientInfo client = this.clientInfoService.enrollClientInfo(mockId, mockSecret);
    if (client != null) {
      log.info("Client ID = " + client.getClientId() + ", Client Secret = " + client.getClientSecret());
    }
    
    User user = this.userAuthService.createTestUser();
    if (user != null) {
      log.info("User ID = " + user.getUserId() + ", User Password = " + user.getPassword());
    }
    

    return ResponseEntity.ok().build();
  }

}
