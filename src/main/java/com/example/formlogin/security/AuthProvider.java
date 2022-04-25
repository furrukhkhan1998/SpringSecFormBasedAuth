package com.example.formlogin.security;

import com.example.formlogin.models.Attempts;
import com.example.formlogin.models.User;
import com.example.formlogin.repository.AttemptsRepository;
import com.example.formlogin.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.security.auth.login.AccountLockedException;
import java.util.Optional;

@Component
public class AuthProvider implements AuthenticationProvider {

    private static final int ATTEMPTS_LIMIT = 5;

    @Autowired
    private SecurityUserDetailsService securityUserDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private AttemptsRepository attemptsRepository;



    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        Optional<Attempts> userAttempts = attemptsRepository.findAttemptsByUsername(username);
        String password = (String) authentication.getCredentials();
        Optional<User> userList = userRepository.findUserByUsername(username);
        User userObject = userList.get();

        if(userObject.getAccountNonLocked() == false){
            throw new LockedException("Account Locked!");
        }

        if (userObject == null){
            return authentication;
        }
        else{
            if(userObject.getPassword().equals(password)){
                if(userAttempts.isPresent()){
                    Attempts attempts = userAttempts.get();
                    attempts.setAttempts(0);
                    attemptsRepository.save(attempts);
                }
                return new UsernamePasswordAuthenticationToken(authentication.getName(), authentication.getCredentials(),authentication.getAuthorities());
            }
            else
            {
                processFailedAttempts(username, userObject);
                throw new BadCredentialsException("Username/Password does not match!");
            }
        }

    }

    private void processFailedAttempts(String username, User user){
        Optional<Attempts> userAttempts = attemptsRepository.findAttemptsByUsername(username);
        Attempts attempts;
        if(!userAttempts.isPresent()){
            attempts = new Attempts();
            attempts.setUsername(username);
            attempts.setAttempts(1);
        }
        else
        {
            attempts = userAttempts.get();
            attempts.setAttempts(attempts.getAttempts() + 1);
        }
        attemptsRepository.save(attempts);

        if(attempts.getAttempts() + 1 > ATTEMPTS_LIMIT){
            user.setAccountNonLocked(false);
            userRepository.save(user);
            throw new LockedException("ACCOUNT LOCKED! TOO MANY INVALID ATTEMPTS!");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {

        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
