package com.FraudDetection.fraud_detection_system.controller;

import com.FraudDetection.fraud_detection_system.model.User;
import com.FraudDetection.fraud_detection_system.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    // Simple SHA-256 password hashing (no Spring Security needed)
    private String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    // =========================
    // REGISTER
    // =========================
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "").trim();
        String password = body.getOrDefault("password", "");
        String fullName = body.getOrDefault("fullName", "").trim();
        String role = body.getOrDefault("role", "USER").trim().toUpperCase();
        String accountNumber = body.getOrDefault("accountNumber", "").trim();

        Map<String, Object> response = new HashMap<>();

        if (username.isEmpty() || password.isEmpty()) {
            response.put("success", false);
            response.put("message", "Username and password are required");
            return ResponseEntity.badRequest().body(response);
        }

        if (!role.equals("USER") && !role.equals("ADMIN")) {
            role = "USER";
        }

        // Password strength
        if (password.length() < 8 ||
                !password.matches(".*[A-Z].*") ||
                !password.matches(".*[0-9].*") ||
                !password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) {
            response.put("success", false);
            response.put("message", "Password must be at least 8 characters and include uppercase, number, and special character");
            return ResponseEntity.badRequest().body(response);
        }

        if (userRepository.findByUsername(username).isPresent()) {
            response.put("success", false);
            response.put("message", "Username already exists");
            return ResponseEntity.badRequest().body(response);
        }

        // Auto account number for USER if not provided
        if (role.equals("USER") && accountNumber.isEmpty()) {
            accountNumber = "ACC" + (System.currentTimeMillis() % 1000000);
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(hashPassword(password));
        user.setFullName(fullName.isEmpty() ? username : fullName);
        user.setRole(role);
        user.setAccountNumber(accountNumber.isEmpty() ? null : accountNumber);
        user.setFailedAttempts(0);
        user.setLockoutUntil(null);
        user.setCreatedAt(LocalDateTime.now());

        userRepository.save(user);

        response.put("success", true);
        response.put("message", "Registration successful");
        response.put("role", role);
        response.put("accountNumber", accountNumber);
        return ResponseEntity.ok(response);
    }

    // =========================
    // LOGIN (3 attempts + 24h lock)
    // =========================
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "").trim();
        String password = body.getOrDefault("password", "");
        String expectedRole = body.getOrDefault("role", "").trim().toUpperCase();

        Map<String, Object> response = new HashMap<>();

        Optional<User> optionalUser = userRepository.findByUsername(username);
        if (optionalUser.isEmpty()) {
            response.put("success", false);
            response.put("message", "Invalid username or password");
            return ResponseEntity.status(401).body(response);
        }

        User user = optionalUser.get();

        // Check 24-hour lockout
        if (user.getLockoutUntil() != null && LocalDateTime.now().isBefore(user.getLockoutUntil())) {
            long minutesLeft = java.time.Duration.between(LocalDateTime.now(), user.getLockoutUntil()).toMinutes();
            response.put("success", false);
            response.put("locked", true);
            response.put("message", "Account locked due to too many failed attempts. Try again in " + minutesLeft + " minutes.");
            response.put("lockoutUntil", user.getLockoutUntil().toString());
            return ResponseEntity.status(403).body(response);
        }

        // If lockout expired, reset
        if (user.getLockoutUntil() != null && LocalDateTime.now().isAfter(user.getLockoutUntil())) {
            user.setFailedAttempts(0);
            user.setLockoutUntil(null);
            userRepository.save(user);
        }

        // Role check (if frontend sends expected role)
        if (!expectedRole.isEmpty() && !expectedRole.equals(user.getRole())) {
            response.put("success", false);
            response.put("message", "This account is not registered as " + expectedRole);
            return ResponseEntity.status(403).body(response);
        }

        // Password check
        String hashedInput = hashPassword(password);
        if (!hashedInput.equals(user.getPassword())) {
            int attempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(attempts);

            if (attempts >= 3) {
                user.setLockoutUntil(LocalDateTime.now().plusHours(24));
                userRepository.save(user);
                response.put("success", false);
                response.put("locked", true);
                response.put("message", "Too many failed attempts. Account locked for 24 hours.");
                response.put("remainingAttempts", 0);
                return ResponseEntity.status(403).body(response);
            }

            userRepository.save(user);
            response.put("success", false);
            response.put("message", "Invalid username or password. Attempts left: " + (3 - attempts));
            response.put("remainingAttempts", 3 - attempts);
            return ResponseEntity.status(401).body(response);
        }

        // Success — reset attempts
        user.setFailedAttempts(0);
        user.setLockoutUntil(null);
        userRepository.save(user);

        String token = UUID.randomUUID().toString();

        response.put("success", true);
        response.put("message", "Login successful");
        response.put("token", token);
        response.put("username", user.getUsername());
        response.put("fullName", user.getFullName());
        response.put("role", user.getRole());
        response.put("accountNumber", user.getAccountNumber());
        return ResponseEntity.ok(response);
    }
}