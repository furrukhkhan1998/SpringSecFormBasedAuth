package com.example.formlogin.repository;

import com.example.formlogin.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findUserByUsername(String username);
}
