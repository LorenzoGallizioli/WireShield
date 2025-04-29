package com.wireshield.ui;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import org.kordamp.ikonli.javafx.FontIcon;

import com.wireshield.enums.warningClass;

import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.shape.Circle;

public class FileCardComponent extends VBox {

    private final VBox detailsPanel;
    private boolean expanded = false;

    public FileCardComponent(String fileName, String filePath, String status, LocalDateTime scanTime, warningClass WarningClass) {
        getStyleClass().add("file-card");
        setSpacing(10);

        // Riga principale con informazioni essenziali
        HBox mainRow = new HBox();
        mainRow.setAlignment(Pos.CENTER_LEFT);
        mainRow.setSpacing(15);

        // Indicatore di stato
        Circle statusCircle = new Circle(6);
        switch (WarningClass) {
            case CLEAR:
                statusCircle.getStyleClass().add("status-indicator");
                statusCircle.getStyleClass().add("clear");
                break;
            case SUSPICIOUS:
                statusCircle.getStyleClass().add("status-indicator");
                statusCircle.getStyleClass().add("suspicious");
                break;
            case DANGEROUS:
                statusCircle.getStyleClass().add("status-indicator");
                statusCircle.getStyleClass().add("dangerous");
                break;
        }

        // Informazioni sul file
        VBox fileInfo = new VBox(5);
        HBox.setHgrow(fileInfo, Priority.ALWAYS);

        Label fileNameLabel = new Label(fileName);
        fileNameLabel.getStyleClass().add("file-name");

        Label filePathLabel = new Label(filePath);
        filePathLabel.getStyleClass().add("file-path");

        fileInfo.getChildren().addAll(fileNameLabel, filePathLabel);

        // Status label
        Label statusLabel = new Label(status);
        statusLabel.getStyleClass().add("file-status");

        switch (WarningClass) {
            case CLEAR:
                statusLabel.getStyleClass().add("status-clean");
                break;
            case SUSPICIOUS:
                statusLabel.getStyleClass().add("status-threat");
                break;
            case DANGEROUS:
                statusLabel.getStyleClass().add("status-warning");
                break;
        }

        // Pulsante di espansione
        Button expandButton = new Button();
        expandButton.getStyleClass().add("expand-button");
        FontIcon icon = new FontIcon("fas-chevron-down");
        expandButton.setGraphic(icon);

        mainRow.getChildren().addAll(statusCircle, fileInfo, statusLabel, expandButton);

        // Panel dei dettagli (inizialmente nascosto)
        detailsPanel = new VBox();
        detailsPanel.getStyleClass().add("details-panel");
        detailsPanel.setSpacing(10);
        detailsPanel.setVisible(false);
        detailsPanel.setManaged(false);

        // Aggiungi dettagli al panel
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");

        addDetailRow(this.detailsPanel, "Scanning Date:", scanTime.format(formatter));
        addDetailRow(this.detailsPanel, "Absolute Path:", filePath);
        //addDetailRow(this.detailsPanel, "SHA256:", hash);
        addDetailRow(this.detailsPanel, "File Status:", status);

        if (!WarningClass.equals(WarningClass.CLEAR)) {
            addDetailRow(detailsPanel, "Minacce Rilevate:", status);
        }

        // Aggiungi i componenti al layout principale
        getChildren().addAll(mainRow, detailsPanel);

        // Gestione del click sul pulsante di espansione
        expandButton.setOnAction(event -> {
            this.expanded = !this.expanded;

            if (expanded) {
                icon.setIconLiteral("fas-chevron-up");
                detailsPanel.setVisible(true);
                detailsPanel.setManaged(true);
            } else {
                icon.setIconLiteral("fas-chevron-down");
                detailsPanel.setVisible(false);
                detailsPanel.setManaged(false);
            }
        });
    }

    private void addDetailRow(VBox container, String title, String value) {
        HBox row = new HBox(10);
        row.setAlignment(Pos.CENTER_LEFT);

        Label titleLabel = new Label(title);
        titleLabel.getStyleClass().add("details-title");
        titleLabel.setPrefWidth(150);

        Label valueLabel = new Label(value);
        valueLabel.getStyleClass().add("details-value");
        valueLabel.setWrapText(true);

        row.getChildren().addAll(titleLabel, valueLabel);
        container.getChildren().add(row);
    }
}
