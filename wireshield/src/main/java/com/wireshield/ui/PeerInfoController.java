package com.wireshield.ui;

import com.wireshield.wireguard.Peer;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;

public class PeerInfoController {

    @FXML
    private Label nameValue;
    @FXML
    private Label publicKeyValue;
    @FXML
    private Label privateKeyValue;
    @FXML
    private Label addressValue;
    @FXML
    private Label endPointValue;
    @FXML
    private Label dnsValue;
    @FXML
    private Label mtuValue;
    @FXML
    private Label presharedKeyValue;
    @FXML
    private Label allowedIPsValue;
    
    @FXML
    private Button showPrivateKeyBtn;
    @FXML
    private Button editPeerBtn;
    @FXML
    private Button deletePeerBtn;
    
    private Peer currentPeer;
    
    private PeerDeletionListener deletionListener;
    
    public void setDeletionListener(PeerDeletionListener listener) {
        this.deletionListener = listener;
    }

    @FXML
    public void initialize() {
        deletePeerBtn.setOnAction(event -> handleDeletePeer());
    }
    
    /**
     * Sets the current peer and updates the UI with its data.
     */
    public void setPeer(Peer peer) {
        this.currentPeer = peer;
        updateUI();
    }
    
    /**
     * Updates the user interface with the peer's data.
     */
    private void updateUI() {
        if (currentPeer == null) return;
        
        nameValue.setText(currentPeer.getName());
        publicKeyValue.setText(currentPeer.getPublicKey());
        addressValue.setText(currentPeer.getAddress());
        endPointValue.setText(currentPeer.getEndPoint());
        dnsValue.setText(currentPeer.getDNS());
        mtuValue.setText(currentPeer.getMTU());
        presharedKeyValue.setText(currentPeer.getPublicKey());
        allowedIPsValue.setText(currentPeer.getAllowedIps());
        
        deletePeerBtn.setDisable(false);
    }
    
    /**
     * Handles the peer edit action.
     */
    private void handleEditPeer() {}
    
    /**
     * Handles the peer deletion action.
     */
    private void handleDeletePeer() {
        Alert confirmDialog = new Alert(AlertType.CONFIRMATION);
        confirmDialog.setTitle("Delete Confirmation");
        confirmDialog.setHeaderText("Delete peer " + currentPeer.getName() + "?");
        confirmDialog.setContentText("This action cannot be undone.");
        
        confirmDialog.showAndWait().ifPresent(response -> {
            if (response == javafx.scene.control.ButtonType.OK) {
            
                if (deletionListener != null) {
                    deletionListener.onPeerDeleted(currentPeer);
                }
                
                deletePeerBtn.setDisable(true);
                
                System.out.println("Peer deleted: " + currentPeer.getName());
            }
        });
    }
}