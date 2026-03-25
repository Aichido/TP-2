package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité représentant un utilisateur en base de données.
 *
 * <p>TP2 : Le mot de passe est désormais hashé avec BCrypt.
 * La politique de mot de passe est renforcée (12 caractères minimum,
 * majuscule, minuscule, chiffre, caractère spécial).
 * Un mécanisme anti brute-force est ajouté (blocage après 5 échecs).</p>
 *
 * <p><b>AVERTISSEMENT</b> : Cette implémentation est partiellement sécurisée
 * mais reste fragile. Le hash circule dans la requête de login,
 * ce qui reste vulnérable au rejeu. Sera corrigé en TP3.</p>
 *
 * @author Tahiry
 * @version 2.0 - TP2
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    /**
     * Mot de passe hashé avec BCrypt.
     * TP2 : plus jamais en clair. Le hash est non réversible.
     */
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "session_token")
    private String sessionToken;

    /**
     * Nombre de tentatives de connexion échouées consécutives.
     * Remis à 0 après une connexion réussie.
     */
    @Column(name = "failed_attempts")
    private int failedAttempts = 0;

    /**
     * Date/heure jusqu'à laquelle le compte est bloqué.
     * Null si le compte n'est pas bloqué.
     */
    @Column(name = "lock_until")
    private LocalDateTime lockUntil;

    public User() {}

    public User(String email, String passwordHash) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.createdAt = LocalDateTime.now();
        this.failedAttempts = 0;
    }

    // ===== Getters & Setters =====

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public String getSessionToken() { return sessionToken; }
    public void setSessionToken(String sessionToken) { this.sessionToken = sessionToken; }

    public int getFailedAttempts() { return failedAttempts; }
    public void setFailedAttempts(int failedAttempts) { this.failedAttempts = failedAttempts; }

    public LocalDateTime getLockUntil() { return lockUntil; }
    public void setLockUntil(LocalDateTime lockUntil) { this.lockUntil = lockUntil; }
}