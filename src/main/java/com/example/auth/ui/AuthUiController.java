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

public class AuthUiController {

    @FXML
    private TextField nameField;

    @FXML
    private TextField emailField;

    @FXML
    private PasswordField passwordField;

    @FXML
    private PasswordField passwordConfirmField;

    @FXML
    private Label passwordStrengthLabel;

    @FXML
    private Label passwordMatchLabel;

    @FXML
    private Label messageLabel;

    private final String apiUrl = "http://localhost:8082/api/auth";

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

    private String escapeJson(String text) {
        if (text == null) {
            return "";
        }

        return text.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}