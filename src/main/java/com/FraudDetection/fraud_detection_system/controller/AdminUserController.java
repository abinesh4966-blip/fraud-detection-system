package com.FraudDetection.fraud_detection_system.controller;

import com.FraudDetection.fraud_detection_system.model.Transaction;
import com.FraudDetection.fraud_detection_system.model.User;
import com.FraudDetection.fraud_detection_system.repository.TransactionRepository;
import com.FraudDetection.fraud_detection_system.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;

@RestController
@RequestMapping("/api/admin/users")
@CrossOrigin(origins = "*")
public class AdminUserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TransactionRepository transactionRepository;

    @GetMapping("/summary")
    public Map<String, Object> summary() {
        Map<String, Object> res = new HashMap<>();
        try {
            List<User> users = userRepository.findAll();
            List<Transaction> txs = transactionRepository.findAll();
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime dayAgo = now.minusHours(24);
            LocalDateTime weekAgo = now.minusDays(7);

            long userRole = 0, adminRole = 0, locked = 0, active24h = 0, active7d = 0;
            for (User u : users) {
                if (u == null) continue;
                String role = u.getRole() != null ? u.getRole().toUpperCase() : "USER";
                if ("ADMIN".equals(role)) adminRole++;
                else userRole++;
                if (u.getLockoutUntil() != null && u.getLockoutUntil().isAfter(now)) locked++;
                if (u.getLastLoginAt() != null && u.getLastLoginAt().isAfter(dayAgo)) active24h++;
                if (u.getLastLoginAt() != null && u.getLastLoginAt().isAfter(weekAgo)) active7d++;
            }

            long flaggedTx = 0;
            for (Transaction t : txs) {
                if (t == null) continue;
                if ("SUSPICIOUS".equals(t.getStatus()) && !t.isFalsePositive()) flaggedTx++;
            }

            res.put("totalUsers", users.size());
            res.put("userAccounts", userRole);
            res.put("adminAccounts", adminRole);
            res.put("lockedAccounts", locked);
            res.put("activeLast24h", active24h);
            res.put("activeLast7d", active7d);
            res.put("totalTransactions", txs.size());
            res.put("flaggedTransactions", flaggedTx);
            res.put("success", true);
        } catch (Exception e) {
            res.put("success", false);
            res.put("message", e.getMessage());
            res.put("totalUsers", 0);
            res.put("userAccounts", 0);
            res.put("adminAccounts", 0);
            res.put("lockedAccounts", 0);
            res.put("activeLast24h", 0);
            res.put("activeLast7d", 0);
            res.put("totalTransactions", 0);
            res.put("flaggedTransactions", 0);
        }
        return res;
    }

    @GetMapping
    public List<Map<String, Object>> listUsers() {
        List<Map<String, Object>> rows = new ArrayList<>();
        try {
            List<User> users = userRepository.findAll();
            List<Transaction> allTx = transactionRepository.findAll();
            LocalDateTime now = LocalDateTime.now();

            Map<String, List<Transaction>> byAccount = new HashMap<>();
            for (Transaction t : allTx) {
                if (t == null || t.getAccountNumber() == null) continue;
                String key = t.getAccountNumber().trim();
                byAccount.computeIfAbsent(key, k -> new ArrayList<>()).add(t);
            }

            for (User u : users) {
                if (u == null) continue;
                String acc = u.getAccountNumber() != null ? u.getAccountNumber().trim() : "";
                List<Transaction> mine = acc.isEmpty()
                        ? Collections.emptyList()
                        : byAccount.getOrDefault(acc, Collections.emptyList());

                long total = mine.size();
                long flagged = 0;
                long cleared = 0;
                int maxRisk = 0;
                for (Transaction t : mine) {
                    if (t == null) continue;
                    int rs = t.getRiskScore() != null ? t.getRiskScore() : 0;
                    if (rs > maxRisk) maxRisk = rs;
                    if ("SUSPICIOUS".equals(t.getStatus()) && !t.isFalsePositive()) flagged++;
                    else cleared++;
                }
                double flaggedRate = total == 0 ? 0.0 : (flagged * 100.0 / total);

                boolean locked = u.getLockoutUntil() != null && u.getLockoutUntil().isAfter(now);
                String activity;
                if (u.getLastLoginAt() == null) activity = "Never logged in";
                else if (u.getLastLoginAt().isAfter(now.minusHours(24))) activity = "Active (24h)";
                else if (u.getLastLoginAt().isAfter(now.minusDays(7))) activity = "Active (7d)";
                else activity = "Inactive";

                String riskBand = "CLEAN";
                if (flagged >= 5 || flaggedRate >= 40 || maxRisk >= 75) riskBand = "HIGH";
                else if (flagged >= 2 || flaggedRate >= 20 || maxRisk >= 50) riskBand = "MEDIUM";
                else if (flagged >= 1) riskBand = "LOW";

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("id", u.getId());
                row.put("username", u.getUsername());
                row.put("fullName", u.getFullName());
                row.put("role", u.getRole());
                row.put("accountNumber", u.getAccountNumber());
                row.put("failedAttempts", u.getFailedAttempts());
                row.put("locked", locked);
                row.put("lockoutUntil", u.getLockoutUntil() != null ? u.getLockoutUntil().toString() : null);
                row.put("createdAt", u.getCreatedAt() != null ? u.getCreatedAt().toString() : null);
                row.put("lastLoginAt", u.getLastLoginAt() != null ? u.getLastLoginAt().toString() : null);
                row.put("activity", activity);
                row.put("txTotal", total);
                row.put("txFlagged", flagged);
                row.put("txCleared", cleared);
                row.put("flaggedRate", Math.round(flaggedRate * 10.0) / 10.0);
                row.put("maxRisk", maxRisk);
                row.put("riskBand", riskBand);
                rows.add(row);
            }

            rows.sort((a, b) -> Long.compare(
                    ((Number) b.get("txFlagged")).longValue(),
                    ((Number) a.get("txFlagged")).longValue()
            ));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return rows;
    }

    @PutMapping("/{id}/unlock")
    public Map<String, Object> unlock(@PathVariable Long id) {
        Map<String, Object> res = new HashMap<>();
        try {
            Optional<User> opt = userRepository.findById(id);
            if (opt.isEmpty()) {
                res.put("success", false);
                res.put("message", "User not found");
                return res;
            }
            User u = opt.get();
            u.setFailedAttempts(0);
            u.setLockoutUntil(null);
            userRepository.save(u);
            res.put("success", true);
            res.put("message", "Account unlocked: " + u.getUsername());
        } catch (Exception e) {
            res.put("success", false);
            res.put("message", e.getMessage());
        }
        return res;
    }
}