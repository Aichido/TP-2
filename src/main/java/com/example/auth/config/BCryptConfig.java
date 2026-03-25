package com.example.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Configuration du bean BCrypt pour le hashage des mots de passe.
 *
 * <p>BCrypt est un algorithme de hashage adaptatif conçu spécifiquement
 * pour les mots de passe. Il intègre automatiquement un sel aléatoire
 * et un facteur de coût (work factor) qui ralentit les attaques brute-force.</p>
 *
 * <p>Note : On utilise uniquement spring-security-crypto, PAS Spring Security Web.
 * Aucun filtre de sécurité HTTP n'est activé.</p>
 */
@Configuration
public class BCryptConfig {

    /**
     * Crée le bean PasswordEncoder avec BCrypt.
     *
     * Le paramètre strength=12 signifie que BCrypt effectuera
     * 2^12 = 4096 rounds de hachage, ce qui prend ~300ms.
     * C'est suffisamment lent pour décourager le brute-force.
     * La valeur par défaut est 10 (1024 rounds).
     *
     * @return un encoder BCrypt avec strength 12
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
