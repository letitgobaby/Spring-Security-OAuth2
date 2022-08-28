package com.example.letitgobaby.app.tokenStore;

import java.util.Optional;
import java.util.Random;

import javax.transaction.Transactional;

import org.springframework.stereotype.Service;

import com.example.letitgobaby.model.TokenStore;
import com.example.letitgobaby.model.TokenStoreRepository;
import com.example.letitgobaby.security.dto.UserInfo;
import com.example.letitgobaby.utils.JWTBuilder;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TokenStoreService {
  
  private final TokenStoreRepository tStoreRepository;
  private final JWTBuilder jwtBuilder;

  @Transactional
  public String getToken(String key) {
    Optional<TokenStore> tStore = this.tStoreRepository.findByObjectKey(key);
    if (tStore.isPresent()) {
      return tStore.get().getObjectValue();
    }
    return null;
  }

  @Transactional
  public String setToken(UserInfo userInfo) throws Exception {
    String refreshToken = this.jwtBuilder.refreshGenerate(userInfo);

    TokenStore entity = null;
    Optional<TokenStore> tStore = this.tStoreRepository.findByUserId(userInfo.getUserId());
    if (tStore.isPresent()) {
      tStore.get().setObjectKey(randomString());
      tStore.get().setObjectValue(refreshToken);
      entity = tStore.get();
    } else {
      entity = new TokenStore().builder()
        .userId(userInfo.getUserId())
        .objectKey(randomString()).objectValue(refreshToken)
        .build();
    }

    this.tStoreRepository.save(entity);
    return entity.getObjectKey();
  }


  private String randomString() {
    int targetStringLength = 10;
    Random random = new Random();
    return random.ints(97, 123)
      .limit(targetStringLength)
      .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
      .toString();
  }

}
