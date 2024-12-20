package com.wireshield.ui;
import javafx.application.Application;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

import com.wireshield.enums.vpnOperations;
import com.wireshield.localfileutils.SystemOrchestrator;

public class UserInterface extends Application {

    private SystemOrchestrator systemOrchestrator;


    @Override
    public void start(Stage primaryStage) {
    	try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("MainView.fxml"));
            Parent root = loader.load();
            Scene scene = new Scene(root, 400, 300);

            primaryStage.setTitle("Applicazione JavaFX");
            primaryStage.setScene(scene);
            primaryStage.show();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Metodo main richiesto per il punto di ingresso
    public static void main(String[] args) {
        launch(args); // Metodo di avvio JavaFX
    }
    
    /**
     * Changes the state of the VPN.
     */
    @FXML
    public void changeVPNState(){
    	SystemOrchestrator so = new SystemOrchestrator();
        so.manageVPN(vpnOperations.START);
    }

    /**
     * Imports a peer.
     */
    public void importPeer(){}

    /**
     * Shows the available peers.
     */
    public void showAvailablePeers(){}
}
