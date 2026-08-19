package com.FraudDetection.fraud_detection_system.controller;

import com.FraudDetection.fraud_detection_system.model.User;
import com.FraudDetection.fraud_detection_system.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    // Simple in-memory failed login tracker
    private final Map<String, Integer> failedAttempts = new ConcurrentHashMap<>();
    private final Map<String, Long> lockoutTime = new ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_MS = 2 * 60 * 1000; // 2 minutes

    // Simple password hashing
    private String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            return password; // fallback
        }
    }

    private boolean isStrongPassword(String password) {
        if (password == null || password.length() < 8) return false;
        boolean hasUpper = password.matches(".*[A-Z].*");
        boolean hasDigit = password.matches(".*\\d.*");
        boolean hasSpecial = password.matches(".*[@#$%^&+=!].*");
        return hasUpper && hasDigit && hasSpecial;
    }

    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody User user) {
        Map<String, Object> response = new HashMap<>();

        if (userRepository.existsByUsername(user.getUsername())) {
            response.put("success", false);
            response.put("message", "Username already exists");
            return response;
        }

        if (!isStrongPassword(user.getPassword())) {
            response.put("success", false);
            response.put("message", "Password must be at least 8 characters and include uppercase, number, and special character");
            return response;
        }

        // Hash password before saving
        user.setPassword(hashPassword(user.getPassword()));
        user.setCreatedAt(LocalDateTime.now());
        user.setRole("ADMIN");
        userRepository.save(user);

        response.put("success", true);
        response.put("message", "Registration successful");
        return response;
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody User loginRequest) {
        Map<String, Object> response = new HashMap<>();
        String username = loginRequest.getUsername();

        // Check lockout
        if (lockoutTime.containsKey(username)) {
            long lockedUntil = lockoutTime.get(username);
            if (System.currentTimeMillis() < lockedUntil) {
                long remaining = (lockedUntil - System.currentTimeMillis()) / 1000;
                response.put("success", false);
                response.put("message", "Account temporarily locked. Try again in " + remaining + " seconds");
                return response;
            } else {
                lockoutTime.remove(username);
                failedAttempts.remove(username);
            }
        }

        Optional<User> userOpt = userRepository.findByUsername(username);
        String hashedInput = hashPassword(loginRequest.getPassword());

        if (userOpt.isPresent() && userOpt.get().getPassword().equals(hashedInput)) {
            // Success - reset attempts
            failedAttempts.remove(username);
            response.put("success", true);
            response.put("message", "Login successful");
            response.put("fullName", userOpt.get().getFullName());
        } else {
            // Failed attempt
            int attempts = failedAttempts.getOrDefault(username, 0) + 1;
            failedAttempts.put(username, attempts);

            if (attempts >= MAX_ATTEMPTS) {
                lockoutTime.put(username, System.currentTimeMillis() + LOCKOUT_DURATION_MS);
                response.put("success", false);
                response.put("message", "Too many failed attempts. Account locked for 2 minutes");
            } else {
                response.put("success", false);
                response.put("message", "Invalid username or password. Attempts left: " + (MAX_ATTEMPTS - attempts));
            }
        }

        return response;
    }
}