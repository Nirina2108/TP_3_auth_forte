package com.example.auth.ui;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Controleur JavaFX de l'interface d'authentification.
 * Cette classe gere :
 * l'inscription,
 * la connexion,
 * la verification visuelle du mot de passe,
 * et les appels HTTP vers l'API Spring Boot.
 */
public class AuthUiController {

    /**
     * Champ pour saisir le nom.
     */
    @FXML
    private TextField nameField;

    /**
     * Champ pour saisir l'email.
     */
    @FXML
    private TextField emailField;

    /**
     * Champ pour saisir le mot de passe.
     */
    @FXML
    private PasswordField passwordField;

    /**
     * Champ pour confirmer le mot de passe.
     */
    @FXML
    private PasswordField passwordConfirmField;

    /**
     * Label pour afficher la force du mot de passe.
     */
    @FXML
    private Label passwordStrengthLabel;

    /**
     * Label pour afficher si les mots de passe correspondent.
     */
    @FXML
    private Label passwordMatchLabel;

    /**
     * Label pour afficher les messages a l'utilisateur.
     */
    @FXML
    private Label messageLabel;

    /**
     * URL de base de l'API d'authentification.
     */
    private final String apiUrl = "http://localhost:8082/api/auth";

    /**
     * Methode appelee automatiquement au chargement de l'interface.
     * Elle ajoute des ecouteurs pour mettre a jour
     * la force du mot de passe et la confirmation.
     */
    @FXML
    public void initialize() {
        passwordField.textProperty().addListener((observable, oldValue, newValue) -> {
            updatePasswordStrength();
            updatePasswordMatch();
        });

        passwordConfirmField.textProperty().addListener((observable, oldValue, newValue) -> {
            updatePasswordMatch();
        });
    }

    /**
     * Gere l'inscription de l'utilisateur.
     * Verifie les champs, compare les mots de passe,
     * controle la validite du mot de passe
     * puis envoie la requete a l'API.
     */
    @FXML
    public void handleRegister() {
        String name = nameField.getText();
        String email = emailField.getText();
        String password = passwordField.getText();
        String passwordConfirm = passwordConfirmField.getText();

        if (name == null || name.isBlank()
                || email == null || email.isBlank()
                || password == null || password.isBlank()
                || passwordConfirm == null || passwordConfirm.isBlank()) {
            messageLabel.setText("Nom, email, mot de passe et confirmation obligatoires");
            messageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        if (!password.equals(passwordConfirm)) {
            messageLabel.setText("Les mots de passe ne sont pas identiques");
            messageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        if (!isPasswordValid(password)) {
            messageLabel.setText("Mot de passe trop faible");
            messageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        String json = "{"
                + "\"name\":\"" + escapeJson(name) + "\","
                + "\"email\":\"" + escapeJson(email) + "\","
                + "\"password\":\"" + escapeJson(password) + "\""
                + "}";

        try {
            String result = sendPost(apiUrl + "/register", json);
            messageLabel.setText("Inscription reussie : " + result);
            messageLabel.setStyle("-fx-text-fill: green;");
        } catch (Exception e) {
            messageLabel.setText("Erreur inscription : " + e.getMessage());
            messageLabel.setStyle("-fx-text-fill: red;");
        }
    }

    /**
     * Gere la connexion de l'utilisateur.
     * Verifie les champs obligatoires
     * puis envoie la requete de connexion a l'API.
     */
    @FXML
    public void handleLogin() {
        String email = emailField.getText();
        String password = passwordField.getText();

        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            messageLabel.setText("Email et mot de passe obligatoires");
            messageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        String json = "{"
                + "\"email\":\"" + escapeJson(email) + "\","
                + "\"password\":\"" + escapeJson(password) + "\""
                + "}";

        try {
            String result = sendPost(apiUrl + "/login", json);
            messageLabel.setText("Connexion reussie : " + result);
            messageLabel.setStyle("-fx-text-fill: green;");
        } catch (Exception e) {
            messageLabel.setText("Erreur connexion : " + e.getMessage());
            messageLabel.setStyle("-fx-text-fill: red;");
        }
    }

    /**
     * Met a jour l'affichage de la force du mot de passe.
     * La force depend de la validite du mot de passe
     * et de sa longueur.
     */
    private void updatePasswordStrength() {
        String password = passwordField.getText();

        if (password == null) {
            password = "";
        }

        if (!isPasswordValid(password)) {
            passwordStrengthLabel.setText("Force : faible");
            passwordStrengthLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        if (password.length() >= 16) {
            passwordStrengthLabel.setText("Force : forte");
            passwordStrengthLabel.setStyle("-fx-text-fill: green;");
        } else {
            passwordStrengthLabel.setText("Force : moyenne");
            passwordStrengthLabel.setStyle("-fx-text-fill: orange;");
        }
    }

    /**
     * Met a jour l'affichage de correspondance
     * entre le mot de passe et sa confirmation.
     */
    private void updatePasswordMatch() {
        String password = passwordField.getText();
        String confirm = passwordConfirmField.getText();

        if (confirm == null || confirm.isBlank()) {
            passwordMatchLabel.setText("");
            return;
        }

        if (password.equals(confirm)) {
            passwordMatchLabel.setText("Les mots de passe correspondent");
            passwordMatchLabel.setStyle("-fx-text-fill: green;");
        } else {
            passwordMatchLabel.setText("Les mots de passe sont differents");
            passwordMatchLabel.setStyle("-fx-text-fill: red;");
        }
    }

    /**
     * Verifie si un mot de passe respecte la regle minimale :
     * 12 caracteres minimum,
     * une majuscule,
     * une minuscule,
     * un chiffre,
     * un caractere special.
     *
     * @param password mot de passe a verifier
     * @return true si le mot de passe est valide, sinon false
     */
    private boolean isPasswordValid(String password) {
        if (password == null || password.length() < 12) {
            return false;
        }

        boolean hasUppercase = false;
        boolean hasLowercase = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);

            if (Character.isUpperCase(c)) {
                hasUppercase = true;
            } else if (Character.isLowerCase(c)) {
                hasLowercase = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else {
                hasSpecial = true;
            }
        }

        return hasUppercase && hasLowercase && hasDigit && hasSpecial;
    }

    /**
     * Envoie une requete HTTP POST a l'API.
     *
     * @param urlText adresse de destination
     * @param jsonBody corps JSON a envoyer
     * @return corps de la reponse HTTP
     * @throws IOException si la requete echoue ou si l'API retourne une erreur
     */
    private String sendPost(String urlText, String jsonBody) throws IOException {
        URL url = new URL(urlText);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Accept", "application/json");
        connection.setDoOutput(true);

        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = jsonBody.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

        int code = connection.getResponseCode();

        InputStream stream;
        if (code >= 200 && code < 300) {
            stream = connection.getInputStream();
        } else {
            stream = connection.getErrorStream();
        }

        String responseBody = readStream(stream);

        if (code >= 200 && code < 300) {
            return responseBody;
        } else {
            throw new IOException("HTTP " + code + " : " + responseBody);
        }
    }

    /**
     * Lit un flux de donnees et retourne son contenu sous forme de texte.
     *
     * @param stream flux a lire
     * @return texte lu dans le flux
     * @throws IOException si une erreur de lecture se produit
     */
    private String readStream(InputStream stream) throws IOException {
        if (stream == null) {
            return "";
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8));
        StringBuilder result = new StringBuilder();
        String line;

        while ((line = reader.readLine()) != null) {
            result.append(line);
        }

        return result.toString();
    }

    /**
     * Echappe les caracteres sensibles dans une chaine
     * avant de construire un texte JSON.
     *
     * @param text texte a proteger
     * @return texte echappe
     */
    private String escapeJson(String text) {
        if (text == null) {
            return "";
        }

        return text.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}