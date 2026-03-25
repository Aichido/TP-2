package com.example.auth;

import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.service.AuthService;
import com.example.auth.service.PasswordPolicyValidator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import javax.security.auth.login.AccountLockedException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests du service d'authentification TP2.
 * Minimum 10 tests requis, 12 implémentés ici.
 *
 * @SpringBootTest  : démarre le contexte Spring complet
 * @Transactional   : chaque test est rollback automatiquement
 * @ActiveProfiles  : utilise application.properties du profil "test" (H2 en mémoire)
 */
@SpringBootTest
@Transactional
@ActiveProfiles("test")
class AuthServiceTest {

	@SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
	private AuthService authService;

	// Mot de passe valide conforme à la politique TP2
	private static final String VALID_PASSWORD = "ValidPass@1234!";

	// =====================================================
	// TESTS POLITIQUE DE MOT DE PASSE
	// =====================================================

	/** Test 1 : Mot de passe trop court */
	@Test
	void testRegister_MotDePasseTropCourt_ThrowsInvalidInput() {
		assertThrows(InvalidInputException.class, () ->
				authService.register("test@test.com", "Court1!")
		);
	}

	/** Test 2 : Mot de passe sans majuscule */
	@Test
	void testRegister_SansMajuscule_ThrowsInvalidInput() {
		assertThrows(InvalidInputException.class, () ->
				authService.register("test@test.com", "minuscule@1234!")
		);
	}

	/** Test 3 : Mot de passe sans chiffre */
	@Test
	void testRegister_SansChiffre_ThrowsInvalidInput() {
		assertThrows(InvalidInputException.class, () ->
				authService.register("test@test.com", "SansChiffre@ABC!")
		);
	}

	/** Test 4 : Mot de passe sans caractère spécial */
	@Test
	void testRegister_SansSpecial_ThrowsInvalidInput() {
		assertThrows(InvalidInputException.class, () ->
				authService.register("test@test.com", "SansSpecial1234")
		);
	}

	// =====================================================
	// TESTS INSCRIPTION
	// =====================================================

	/** Test 5 : Inscription réussie avec mot de passe valide */
	@Test
	void testRegister_OK() {
		var user = authService.register("nouveau@test.com", VALID_PASSWORD);
		assertNotNull(user.getId());
		assertEquals("nouveau@test.com", user.getEmail());
	}

	/** Test 6 : Le mot de passe stocké est bien hashé (pas en clair) */
	@Test
	void testRegister_MotDePasseEstHashe_PasClair() {
		var user = authService.register("hash@test.com", VALID_PASSWORD);
		// Le hash BCrypt ne doit jamais être identique au mot de passe clair
		assertNotEquals(VALID_PASSWORD, user.getPasswordHash());
		// Le hash BCrypt commence toujours par "$2a$" ou "$2b$"
		assertTrue(user.getPasswordHash().startsWith("$2"));
	}

	/** Test 7 : Inscription refusée si email déjà existant */
	@Test
	void testRegister_EmailDeja_ThrowsConflict() {
		authService.register("doublon@test.com", VALID_PASSWORD);
		assertThrows(ResourceConflictException.class, () ->
				authService.register("doublon@test.com", VALID_PASSWORD)
		);
	}

	// =====================================================
	// TESTS CONNEXION
	// =====================================================

	/** Test 8 : Login réussi */
	@Test
	void testLogin_OK() {
		authService.register("login@test.com", VALID_PASSWORD);
		String token = authService.login("login@test.com", VALID_PASSWORD);
		assertNotNull(token);
		assertFalse(token.isBlank());
	}

	/** Test 9 : Login KO mauvais mot de passe */
	@Test
	void testLogin_MauvaisMotDePasse_ThrowsAuthFailed() {
		authService.register("wrong@test.com", VALID_PASSWORD);
		assertThrows(AuthenticationFailedException.class, () ->
				authService.login("wrong@test.com", "MauvaisPass@1234!")
		);
	}

	/**
	 * Test 10 : Non-divulgation des erreurs.
	 * Le message d'erreur doit être IDENTIQUE pour un email inconnu
	 * et pour un mauvais mot de passe. Ainsi, un attaquant ne peut
	 * pas savoir si un email existe ou non.
	 */
	@Test
	void testLogin_NonDivulgation_MemeMessageErreur() {
		authService.register("exist@test.com", VALID_PASSWORD);

		// Cas 1 : email inconnu
		AuthenticationFailedException ex1 = assertThrows(
				AuthenticationFailedException.class,
				() -> authService.login("inconnu@test.com", VALID_PASSWORD)
		);

		// Cas 2 : mauvais mot de passe
		AuthenticationFailedException ex2 = assertThrows(
				AuthenticationFailedException.class,
				() -> authService.login("exist@test.com", "MauvaisPass@1234!")
		);

		// Les deux messages doivent être strictement identiques
		assertEquals(ex1.getMessage(), ex2.getMessage(),
				"Les messages d'erreur doivent être identiques pour ne pas divulguer d'information");
	}

	/**
	 * Test 11 : Blocage après 5 tentatives échouées.
	 * La 6e tentative doit lever AccountLockedException.
	 */
	@Test
	void testBruteForce_BloquageApres5Echecs() {
		authService.register("brute@test.com", VALID_PASSWORD);

		// 5 tentatives avec mauvais mot de passe
		for (int i = 0; i < 5; i++) {
			int attempt = i;
			assertThrows(AuthenticationFailedException.class, () ->
					authService.login("brute@test.com", "MauvaisPass@" + attempt + "!")
			);
		}

		// La 6e tentative doit être bloquée, même avec le bon mot de passe
		assertThrows(AccountLockedException.class, () ->
				authService.login("brute@test.com", VALID_PASSWORD)
		);
	}

	/**
	 * Test 12 : Accès /api/me avec token valide.
	 */
	@Test
	void testGetMe_ApresLogin_OK() {
		authService.register("me@test.com", VALID_PASSWORD);
		String token = authService.login("me@test.com", VALID_PASSWORD);
		var user = authService.getUserByToken(token);
		assertEquals("me@test.com", user.getEmail());
	}

	// =====================================================
	// TESTS VALIDATEUR (classe PasswordPolicyValidator)
	// =====================================================

	/** Test bonus : Force du mot de passe - WEAK */
	@Test
	void testPasswordStrength_Weak() {
		var strength = PasswordPolicyValidator.getStrength("court");
		assertEquals(PasswordPolicyValidator.PasswordStrength.WEAK, strength);
	}

	/** Test bonus : Force du mot de passe - STRONG */
	@Test
	void testPasswordStrength_Strong() {
		var strength = PasswordPolicyValidator.getStrength("TresLongMotDePasse@1234!!");
		assertEquals(PasswordPolicyValidator.PasswordStrength.STRONG, strength);
	}
}