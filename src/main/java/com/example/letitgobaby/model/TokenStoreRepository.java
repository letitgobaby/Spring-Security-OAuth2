package com.example.letitgobaby.model;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenStoreRepository extends JpaRepository<TokenStore, Long> {
  
  Optional<TokenStore> findByUserId(String userId);

}
