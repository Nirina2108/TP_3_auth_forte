package com.example.auth.repository;

import com.example.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Repository permettant d'acceder aux utilisateurs en base de donnees.
 * Il herite de JpaRepository pour beneficier des operations CRUD.
 */
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Recherche un utilisateur par son email.
     *
     * @param email email de l'utilisateur
     * @return utilisateur trouve ou vide si aucun resultat
     */
    Optional<User> findByEmail(String email);

    /**
     * Recherche un utilisateur par son token.
     *
     * @param token token de session
     * @return utilisateur trouve ou vide si aucun resultat
     */
    Optional<User> findByToken(String token);
}