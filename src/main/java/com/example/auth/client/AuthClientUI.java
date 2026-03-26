package com.example.auth.client;

import com.example.auth.service.HmacService;
import com.example.auth.validator.PasswordStrengthUtil;
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Separator;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Interface JavaFX simple pour tester l'authentification TP3.
 *
 * Cette interface permet :
 * - l'inscription
 * - la connexion sécurisée avec nonce + timestamp + hmac
 * - le test de /me
 * - le logout
 *
 * @author Poun
 * @version 3.0
 */
public class AuthClientUI extends Application {

    /**
     * URL de base du backend.
     */
    private static final String BASE_URL = "http://localhost:8000/api/auth";

    /**
     * Secret partagé pour le HMAC.
     * Il doit être identique à celui du backend.
     */
    private static final String HMAC_SECRET = "secret";

    private TextField registerNameField;
    private TextField registerEmailField;
    private PasswordField registerPasswordField;
    private PasswordField registerConfirmPasswordField;
    private Label passwordStatusLabel;
    private Label registerMessageLabel;

    private TextField loginEmailField;
    private TextField loginNonceField;
    private TextField loginTimestampField;
    private TextField loginHmacField;
    private Label loginMessageLabel;

    private TextField tokenField;
    private Label sessionMessageLabel;

    private final PasswordStrengthUtil passwordStrengthUtil = new PasswordStrengthUtil();
    private final HmacService hmacService = new HmacService();

    /**
     * Démarre l'interface JavaFX.
     *
     * @param stage fenêtre principale
     */
    @Override
    public void start(Stage stage) {
        Label titleLabel = new Label("TP3 - Authentification forte");
        titleLabel.setStyle("-fx-font-size: 20px; -fx-font-weight: bold;");

        Label registerTitle = new Label("Inscription");
        registerTitle.setStyle("-fx-font-size: 16px; -fx-font-weight: bold;");

        registerNameField = new TextField();
        registerNameField.setPromptText("Nom");

        registerEmailField = new TextField();
        registerEmailField.setPromptText("Email");

        registerPasswordField = new PasswordField();
        registerPasswordField.setPromptText("Mot de passe");

        registerConfirmPasswordField = new PasswordField();
        registerConfirmPasswordField.setPromptText("Confirmer le mot de passe");

        passwordStatusLabel = new Label("Saisissez un mot de passe");
        passwordStatusLabel.setStyle("-fx-text-fill: red; -fx-font-weight: bold;");

        registerMessageLabel = new Label();

        Button registerButton = new Button("S'inscrire");
        registerButton.setMaxWidth(Double.MAX_VALUE);
        registerButton.setOnAction(event -> handleRegister());

        registerPasswordField.textProperty().addListener((observable, oldValue, newValue) -> updatePasswordIndicator());
        registerConfirmPasswordField.textProperty().addListener((observable, oldValue, newValue) -> updatePasswordIndicator());

        Label loginTitle = new Label("Connexion TP3");
        loginTitle.setStyle("-fx-font-size: 16px; -fx-font-weight: bold;");

        loginEmailField = new TextField();
        loginEmailField.setPromptText("Email");

        loginNonceField = new TextField();
        loginNonceField.setPromptText("Nonce");

        loginTimestampField = new TextField();
        loginTimestampField.setPromptText("Timestamp");

        loginHmacField = new TextField();
        loginHmacField.setPromptText("HMAC");

        loginMessageLabel = new Label();

        Button nonceButton = new Button("Générer nonce");
        nonceButton.setOnAction(event -> loginNonceField.setText("nonce-" + UUID.randomUUID()));

        Button timestampButton = new Button("Générer timestamp");
        timestampButton.setOnAction(event -> loginTimestampField.setText(String.valueOf(System.currentTimeMillis() / 1000)));

        Button hmacButton = new Button("Générer HMAC");
        hmacButton.setOnAction(event -> generateHmac());

        Button loginButton = new Button("Se connecter");
        loginButton.setMaxWidth(Double.MAX_VALUE);
        loginButton.setOnAction(event -> handleLogin());

        HBox hmacToolsBox = new HBox(10, nonceButton, timestampButton, hmacButton);
        hmacToolsBox.setAlignment(Pos.CENTER);

        Label sessionTitle = new Label("Session");
        sessionTitle.setStyle("-fx-font-size: 16px; -fx-font-weight: bold;");

        tokenField = new TextField();
        tokenField.setPromptText("Token");
        tokenField.setEditable(false);

        sessionMessageLabel = new Label();

        Button meButton = new Button("Tester /me");
        meButton.setOnAction(event -> handleMe());

        Button logoutButton = new Button("Logout");
        logoutButton.setOnAction(event -> handleLogout());

        HBox sessionButtonsBox = new HBox(10, meButton, logoutButton);
        sessionButtonsBox.setAlignment(Pos.CENTER);

        VBox root = new VBox(10);
        root.setPadding(new Insets(20));
        root.setAlignment(Pos.TOP_CENTER);

        root.getChildren().addAll(
                titleLabel,
                new Separator(),

                registerTitle,
                registerNameField,
                registerEmailField,
                registerPasswordField,
                registerConfirmPasswordField,
                passwordStatusLabel,
                registerButton,
                registerMessageLabel,

                new Separator(),

                loginTitle,
                loginEmailField,
                loginNonceField,
                loginTimestampField,
                loginHmacField,
                hmacToolsBox,
                loginButton,
                loginMessageLabel,

                new Separator(),

                sessionTitle,
                tokenField,
                sessionButtonsBox,
                sessionMessageLabel
        );

        Scene scene = new Scene(root, 520, 760);

        stage.setTitle("TP3 Auth Client");
        stage.setScene(scene);
        stage.show();
    }

    /**
     * Met à jour l'indicateur de mot de passe.
     */
    private void updatePasswordIndicator() {
        String password = registerPasswordField.getText();
        String confirmPassword = registerConfirmPasswordField.getText();

        String level = passwordStrengthUtil.evaluate(password);
        String message = passwordStrengthUtil.getMessage(password, confirmPassword);

        passwordStatusLabel.setText(message);

        if (!passwordStrengthUtil.isPolicyValid(password)) {
            passwordStatusLabel.setStyle("-fx-text-fill: red; -fx-font-weight: bold;");
            return;
        }

        if (!passwordStrengthUtil.passwordsMatch(password, confirmPassword)) {
            passwordStatusLabel.setStyle("-fx-text-fill: red; -fx-font-weight: bold;");
            return;
        }

        if (PasswordStrengthUtil.GREEN.equals(level)) {
            passwordStatusLabel.setStyle("-fx-text-fill: green; -fx-font-weight: bold;");
        } else {
            passwordStatusLabel.setStyle("-fx-text-fill: orange; -fx-font-weight: bold;");
        }
    }

    /**
     * Envoie une inscription réelle au backend.
     */
    private void handleRegister() {
        String name = registerNameField.getText();
        String email = registerEmailField.getText();
        String password = registerPasswordField.getText();
        String confirmPassword = registerConfirmPasswordField.getText();

        if (name == null || name.isBlank()) {
            registerMessageLabel.setText("Le nom est obligatoire.");
            registerMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        if (email == null || email.isBlank()) {
            registerMessageLabel.setText("L'email est obligatoire.");
            registerMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        if (!passwordStrengthUtil.isPolicyValid(password)) {
            registerMessageLabel.setText("Le mot de passe ne respecte pas les règles.");
            registerMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        if (!passwordStrengthUtil.passwordsMatch(password, confirmPassword)) {
            registerMessageLabel.setText("La confirmation du mot de passe est différente.");
            registerMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        try {
            String json = String.format(
                    "{\"name\":\"%s\",\"email\":\"%s\",\"password\":\"%s\"}",
                    escapeJson(name),
                    escapeJson(email),
                    escapeJson(password)
            );

            HttpURLConnection connection = createConnection(BASE_URL + "/register", "POST", null);
            writeBody(connection, json);

            int code = connection.getResponseCode();
            String response = readResponse(connection);

            if (code == 200 || code == 201) {
                registerMessageLabel.setText("Inscription réussie : " + response);
                registerMessageLabel.setStyle("-fx-text-fill: green;");
            } else {
                registerMessageLabel.setText("Erreur inscription (" + code + ") : " + response);
                registerMessageLabel.setStyle("-fx-text-fill: red;");
            }
        } catch (Exception e) {
            registerMessageLabel.setText("Erreur inscription : " + e.getMessage());
            registerMessageLabel.setStyle("-fx-text-fill: red;");
        }
    }

    /**
     * Génère automatiquement le HMAC à partir de email, nonce et timestamp.
     */
    private void generateHmac() {
        String email = loginEmailField.getText();
        String nonce = loginNonceField.getText();
        String timestampText = loginTimestampField.getText();

        // 🔥 ON UTILISE LE MOT DE PASSE
        String password = registerPasswordField.getText();

        if (email == null || email.isBlank()
                || nonce == null || nonce.isBlank()
                || timestampText == null || timestampText.isBlank()
                || password == null || password.isBlank()) {

            loginMessageLabel.setText("Email, nonce, timestamp et mot de passe sont obligatoires.");
            loginMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        try {
            long timestamp = Long.parseLong(timestampText);

            String message = hmacService.buildMessage(email, nonce, timestamp);

            // 🔥 CORRECTION ICI
            String hmac = hmacService.hmacSha256(password, message);

            loginHmacField.setText(hmac);
            loginMessageLabel.setText("HMAC généré.");
            loginMessageLabel.setStyle("-fx-text-fill: green;");

        } catch (NumberFormatException e) {
            loginMessageLabel.setText("Timestamp invalide.");
            loginMessageLabel.setStyle("-fx-text-fill: red;");
        }
    }
    /**
     * Envoie une vraie connexion TP3 au backend.
     */
    private void handleLogin() {
        String email = loginEmailField.getText();
        String nonce = loginNonceField.getText();
        String timestampText = loginTimestampField.getText();
        String hmac = loginHmacField.getText();

        if (email == null || email.isBlank()
                || nonce == null || nonce.isBlank()
                || timestampText == null || timestampText.isBlank()
                || hmac == null || hmac.isBlank()) {
            loginMessageLabel.setText("Tous les champs sont obligatoires.");
            loginMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        try {
            long timestamp = Long.parseLong(timestampText);

            String json = String.format(
                    "{\"email\":\"%s\",\"nonce\":\"%s\",\"timestamp\":%d,\"hmac\":\"%s\"}",
                    escapeJson(email),
                    escapeJson(nonce),
                    timestamp,
                    escapeJson(hmac)
            );

            HttpURLConnection connection = createConnection(BASE_URL + "/login", "POST", null);
            writeBody(connection, json);

            int code = connection.getResponseCode();
            String response = readResponse(connection);

            if (code == 200) {
                loginMessageLabel.setText("Connexion réussie : " + response);
                loginMessageLabel.setStyle("-fx-text-fill: green;");
                String token = extractToken(response);
                tokenField.setText(token);
            } else {
                loginMessageLabel.setText("Erreur connexion (" + code + ") : " + response);
                loginMessageLabel.setStyle("-fx-text-fill: red;");
            }
        } catch (NumberFormatException e) {
            loginMessageLabel.setText("Timestamp invalide.");
            loginMessageLabel.setStyle("-fx-text-fill: red;");
        } catch (Exception e) {
            loginMessageLabel.setText("Erreur connexion : " + e.getMessage());
            loginMessageLabel.setStyle("-fx-text-fill: red;");
        }
    }

    /**
     * Teste /me avec le token courant.
     */
    private void handleMe() {
        String token = tokenField.getText();

        if (token == null || token.isBlank()) {
            sessionMessageLabel.setText("Aucun token disponible.");
            sessionMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        try {
            HttpURLConnection connection = createConnection(BASE_URL + "/me", "GET", token);
            int code = connection.getResponseCode();
            String response = readResponse(connection);

            if (code == 200) {
                sessionMessageLabel.setText("/me OK : " + response);
                sessionMessageLabel.setStyle("-fx-text-fill: green;");
            } else {
                sessionMessageLabel.setText("Erreur /me (" + code + ") : " + response);
                sessionMessageLabel.setStyle("-fx-text-fill: red;");
            }
        } catch (Exception e) {
            sessionMessageLabel.setText("Erreur /me : " + e.getMessage());
            sessionMessageLabel.setStyle("-fx-text-fill: red;");
        }
    }

    /**
     * Fait le logout avec le token courant.
     */
    private void handleLogout() {
        String token = tokenField.getText();

        if (token == null || token.isBlank()) {
            sessionMessageLabel.setText("Aucun token disponible.");
            sessionMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        try {
            HttpURLConnection connection = createConnection(BASE_URL + "/logout", "POST", token);
            writeBody(connection, "");

            int code = connection.getResponseCode();
            String response = readResponse(connection);

            if (code == 200) {
                sessionMessageLabel.setText("Logout réussi : " + response);
                sessionMessageLabel.setStyle("-fx-text-fill: green;");
                tokenField.clear();
            } else {
                sessionMessageLabel.setText("Erreur logout (" + code + ") : " + response);
                sessionMessageLabel.setStyle("-fx-text-fill: red;");
            }
        } catch (Exception e) {
            sessionMessageLabel.setText("Erreur logout : " + e.getMessage());
            sessionMessageLabel.setStyle("-fx-text-fill: red;");
        }
    }

    /**
     * Crée une connexion HTTP.
     *
     * @param urlString url cible
     * @param method GET ou POST
     * @param token token éventuel
     * @return connexion HTTP
     * @throws Exception si erreur
     */
    private HttpURLConnection createConnection(String urlString, String method, String token) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        connection.setRequestMethod(method);
        connection.setRequestProperty("Content-Type", "application/json");

        if (token != null && !token.isBlank()) {
            connection.setRequestProperty("Authorization", "Bearer " + token);
        }

        if ("POST".equals(method)) {
            connection.setDoOutput(true);
        }

        return connection;
    }

    /**
     * Écrit le corps JSON dans la requête.
     *
     * @param connection connexion HTTP
     * @param body contenu JSON
     * @throws Exception si erreur
     */
    private void writeBody(HttpURLConnection connection, String body) throws Exception {
        try (OutputStream outputStream = connection.getOutputStream()) {
            outputStream.write(body.getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * Lit la réponse HTTP.
     *
     * @param connection connexion HTTP
     * @return texte réponse
     * @throws Exception si erreur
     */
    private String readResponse(HttpURLConnection connection) throws Exception {
        InputStream stream;

        if (connection.getResponseCode() >= 200 && connection.getResponseCode() < 400) {
            stream = connection.getInputStream();
        } else {
            stream = connection.getErrorStream();
        }

        if (stream == null) {
            return "";
        }

        StringBuilder response = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        }

        return response.toString();
    }

    /**
     * Extrait le token d'une réponse JSON simple.
     *
     * @param response réponse JSON
     * @return token ou chaîne vide
     */
    /**
     * Extrait le token d'une réponse JSON simple.
     *
     * @param response réponse JSON
     * @return token ou chaîne vide
     */
    private String extractToken(String response) {
        if (response == null || !response.contains("\"accessToken\"")) {
            return "";
        }

        int tokenIndex = response.indexOf("\"accessToken\"");
        int colonIndex = response.indexOf(":", tokenIndex);
        int firstQuote = response.indexOf("\"", colonIndex + 1);
        int secondQuote = response.indexOf("\"", firstQuote + 1);

        if (firstQuote == -1 || secondQuote == -1) {
            return "";
        }

        return response.substring(firstQuote + 1, secondQuote);
    }

    /**
     * Échappe les guillemets pour JSON.
     *
     * @param value texte d'entrée
     * @return texte échappé
     */
    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\"", "\\\"");
    }

    /**
     * Lance l'application.
     *
     * @param args arguments
     */
    public static void main(String[] args) {
        launch(args);
    }
}