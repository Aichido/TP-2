package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.AccountLockedException;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service principal d'authentification.
 *
 * <p>TP2 améliorations par rapport à TP1 :</p>
 * <ul>
 *   <li>Politique de mot de passe stricte (12 car, complexité)</li>
 *   <li>Hashage BCrypt des mots de passe</li>
 *   <li>Protection anti brute-force (5 échecs = blocage 2 min)</li>
 * </ul>
 *
 * <p><b>AVERTISSEMENT</b> : TP2 améliore le stockage mais ne protège pas
 * encore contre le rejeu. La phase de login repose encore sur une preuve
 * directement dérivée de la saisie utilisateur.
 * Si un attaquant capture la requête de login, il peut tenter de la rejouer.
 * Sera corrigé en TP3 avec HMAC + nonce + timestamp.</p>
 *
 * @author TonNom
 * @version 2.0 - TP2
 */
@SuppressWarnings("JavadocReference")
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    /** Nombre maximum de tentatives avant blocage */
    private static final int MAX_ATTEMPTS = 5;

    /** Durée de blocage en minutes */
    private static final int LOCK_DURATION_MINUTES = 2;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Injection par constructeur (meilleure pratique Spring).
     * Spring injecte automatiquement le bean PasswordEncoder défini dans BCryptConfig.
     */
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Inscrit un nouvel utilisateur avec politique de mot de passe stricte.
     *
     * <p>Processus :</p>
     * <ol>
     *   <li>Validation email (format)</li>
     *   <li>Validation mot de passe (politique TP2)</li>
     *   <li>Vérification unicité email</li>
     *   <li>Hashage BCrypt du mot de passe</li>
     *   <li>Persistance en base</li>
     * </ol>
     *
     * @param email    l'adresse email de l'utilisateur
     * @param password le mot de passe en clair (jamais stocké tel quel)
     * @return l'utilisateur créé
     * @throws InvalidInputException     si les données sont invalides
     * @throws ResourceConflictException si l'email existe déjà
     */
    public User register(String email, String password) {
        // 1. Validation email
        if (email == null || email.isBlank()) {
            throw new InvalidInputException("L'email ne peut pas être vide");
        }
        if (!email.contains("@") || !email.contains(".")) {
            throw new InvalidInputException("Format d'email invalide");
        }

        // 2. Validation mot de passe (politique TP2 stricte)
        PasswordPolicyValidator.validate(password);

        // 3. Vérifier unicité email
        if (userRepository.findByEmail(email).isPresent()) {
            logger.warn("Tentative d'inscription avec email déjà existant : {}", email);
            throw new ResourceConflictException("Cet email est déjà utilisé");
        }

        // 4. Hasher le mot de passe avec BCrypt
        //    Le mot de passe en clair n'est JAMAIS sauvegardé
        String hashedPassword = passwordEncoder.encode(password);

        // 5. Créer et sauvegarder l'utilisateur
        User user = new User(email, hashedPassword);
        userRepository.save(user);

        logger.info("Inscription réussie pour : {}", email);
        return user;
    }

    /**
     * Authentifie un utilisateur avec protection anti brute-force.
     *
     * <p>Processus :</p>
     * <ol>
     *   <li>Validation des entrées</li>
     *   <li>Recherche de l'utilisateur</li>
     *   <li>Vérification du blocage de compte</li>
     *   <li>Vérification BCrypt du mot de passe</li>
     *   <li>Gestion des tentatives échouées ou succès</li>
     *   <li>Génération du token de session</li>
     * </ol>
     *
     * @param email    l'email de l'utilisateur
     * @param password le mot de passe en clair
     * @return le token de session généré
     * @throws InvalidInputException         si les champs sont vides
     * @throws AccountLockedException        si le compte est bloqué (HTTP 429)
     * @throws AuthenticationFailedException si les identifiants sont incorrects
     */
    public String login(String email, String password) {
        // 1. Validation des entrées
        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            throw new InvalidInputException("Email et mot de passe requis");
        }

        // 2. Rechercher l'utilisateur
        User user = userRepository.findByEmail(email).orElse(null);

        // Si l'utilisateur n'existe pas, on rejette avec le MÊME message
        // que pour un mauvais mot de passe (non-divulgation d'information)
        if (user == null) {
            logger.warn("Tentative de connexion avec email inconnu : {}", email);
            throw new AuthenticationFailedException("Email ou mot de passe incorrect");
        }

        // 3. Vérifier si le compte est actuellement bloqué
        if (user.getLockUntil() != null
                && LocalDateTime.now().isBefore(user.getLockUntil())) {
            logger.warn("Tentative de connexion sur compte bloqué : {}", email);
            throw new AccountLockedException(
                    "Compte temporairement bloqué suite à trop de tentatives. " +
                            "Réessayez dans " + LOCK_DURATION_MINUTES + " minutes."
            );
        }

        // 4. Vérifier le mot de passe avec BCrypt
        //    passwordEncoder.matches(plaintext, hash) compare sans révéler le hash
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            // Incrémenter le compteur d'échecs
            int newAttempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(newAttempts);

            // Bloquer le compte si le seuil est atteint
            if (newAttempts >= MAX_ATTEMPTS) {
                user.setLockUntil(LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES));
                logger.warn("Compte bloqué pour {} suite à {} échecs", email, newAttempts);
            }

            userRepository.save(user);
            logger.warn("Échec connexion ({}/{}) pour : {}", newAttempts, MAX_ATTEMPTS, email);

            // IMPORTANT : même message d'erreur que "email inconnu"
            throw new AuthenticationFailedException("Email ou mot de passe incorrect");
        }

        // 5. Succès : réinitialiser le compteur d'échecs
        user.setFailedAttempts(0);
        user.setLockUntil(null);

        // 6. Générer un token de session
        String token = UUID.randomUUID().toString();
        user.setSessionToken(token);
        userRepository.save(user);

        logger.info("Connexion réussie pour : {}", email);
        return token;
    }

    /**
     * Récupère un utilisateur à partir de son token de session.
     *
     * @param token le token de session
     * @return l'utilisateur correspondant
     * @throws AuthenticationFailedException si le token est invalide ou absent
     */
    public User getUserByToken(String token) {
        if (token == null || token.isBlank()) {
            throw new AuthenticationFailedException("Token manquant");
        }
        return userRepository.findBySessionToken(token)
                .orElseThrow(() ->
                        new AuthenticationFailedException("Token invalide ou session expirée")
                );
    }
}