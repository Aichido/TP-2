package com.example.auth.service;

import com.example.auth.exception.InvalidInputException;
import java.util.regex.Pattern;

/**
 * Validateur de politique de mot de passe.
 *
 * <p>Règles obligatoires TP2 :</p>
 * <ul>
 *   <li>Minimum 12 caractères</li>
 *   <li>Au moins 1 lettre majuscule</li>
 *   <li>Au moins 1 lettre minuscule</li>
 *   <li>Au moins 1 chiffre</li>
 *   <li>Au moins 1 caractère spécial</li>
 * </ul>
 *
 * <p><b>AVERTISSEMENT</b> : Cette implémentation est volontairement
 * incomplète et ne doit jamais être utilisée en production sans
 * vérifications supplémentaires (liste noire, entropie, etc.).</p>
 *
 * @author Tahiry
 * @version 2.0 - TP2
 */
public class PasswordPolicyValidator {

    // Longueur minimale imposée par le cahier des charges TP2
    private static final int MIN_LENGTH = 12;

    // Patterns compilés une seule fois (meilleure performance)
    private static final Pattern HAS_UPPERCASE = Pattern.compile("[A-Z]");
    private static final Pattern HAS_LOWERCASE = Pattern.compile("[a-z]");
    private static final Pattern HAS_DIGIT     = Pattern.compile("[0-9]");
    private static final Pattern HAS_SPECIAL   = Pattern.compile("[^A-Za-z0-9]");

    /**
     * Constructeur privé : cette classe n'est pas instanciable.
     * Toutes ses méthodes sont statiques.
     */
    private PasswordPolicyValidator() {}

    /**
     * Valide qu'un mot de passe respecte la politique TP2.
     * Lance une exception si une règle est violée.
     *
     * @param password le mot de passe à valider
     * @throws InvalidInputException si le mot de passe ne respecte pas la politique
     */
    public static void validate(String password) {
        if (password == null || password.isBlank()) {
            throw new InvalidInputException("Le mot de passe ne peut pas être vide");
        }
        if (password.length() < MIN_LENGTH) {
            throw new InvalidInputException(
                    "Le mot de passe doit faire au moins " + MIN_LENGTH + " caractères"
            );
        }
        if (!HAS_UPPERCASE.matcher(password).find()) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins une lettre majuscule"
            );
        }
        if (!HAS_LOWERCASE.matcher(password).find()) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins une lettre minuscule"
            );
        }
        if (!HAS_DIGIT.matcher(password).find()) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins un chiffre"
            );
        }
        if (!HAS_SPECIAL.matcher(password).find()) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins un caractère spécial (!@#$...)"
            );
        }
    }

    /**
     * Évalue la force d'un mot de passe.
     * Utilisé par le client Java pour l'indicateur rouge/orange/vert.
     *
     * @param password le mot de passe à évaluer
     * @return la force du mot de passe
     */
    public static PasswordStrength getStrength(String password) {
        if (password == null || password.isBlank()) {
            return PasswordStrength.WEAK;
        }

        // Non conforme = rouge
        try {
            validate(password);
        } catch (InvalidInputException e) {
            return PasswordStrength.WEAK;
        }

        // Conforme mais faible : exactement 12 caractères ou peu varié
        int score = 0;
        if (password.length() >= 16) score++;
        if (password.length() >= 20) score++;
        if (HAS_SPECIAL.matcher(password).results().count() >= 2) score++;
        if (HAS_DIGIT.matcher(password).results().count() >= 2) score++;

        if (score >= 2) {
            return PasswordStrength.STRONG;   // Vert
        } else {
            return PasswordStrength.MEDIUM;   // Orange
        }
    }

    /**
     * Énumération de la force d'un mot de passe.
     */
    public enum PasswordStrength {
        WEAK,    // Rouge  - non conforme
        MEDIUM,  // Orange - conforme mais faible
        STRONG   // Vert   - conforme et robuste
    }
}