package com.nd2k.security.controller;

import com.nd2k.security.model.ChangePasswordRequest;
import com.nd2k.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/user")
@RequiredArgsConstructor
@SuppressWarnings("unused")
public class UserController {

    private final AuthenticationService authenticationService;

    @GetMapping
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello from secured endpoint");
    }

    @PutMapping("/change-password")
    public ResponseEntity<String> changePassword(
            @RequestBody ChangePasswordRequest changePasswordRequest,
            Principal connectedUser) {
        authenticationService.changePassword(
                changePasswordRequest, connectedUser);
        return ResponseEntity.ok("Password changed successfully");
    }
}
